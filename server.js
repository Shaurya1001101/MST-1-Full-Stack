// Zero-dependency Node server: static files + JWT (HS256) auth + posts API
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const SECRET = process.env.JWT_SECRET || 'change-this-secret-in-production';
const TOKEN_TTL = 60 * 60; // 1 hour
const DATA_FILE = path.join(__dirname, 'posts.json');
const USERS_FILE = path.join(__dirname, 'users.json');
const PUBLIC_DIR = path.join(__dirname, 'public');

/* ---------- Users & password hashing (scrypt + random salt) ---------- */
function hashPassword(password, salt = crypto.randomBytes(16).toString('hex')) {
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return { salt, hash };
}

function checkPassword(password, user) {
  const given = crypto.scryptSync(password, user.salt, 64);
  const stored = Buffer.from(user.hash, 'hex');
  return given.length === stored.length && crypto.timingSafeEqual(given, stored);
}

// Create default accounts the first time the server starts
function loadUsers() {
  if (!fs.existsSync(USERS_FILE)) {
    const users = {
      admin:  { ...hashPassword('Admin@123'),  role: 'admin'  },
      viewer: { ...hashPassword('Viewer@123'), role: 'viewer' },
    };
    fs.writeFileSync(USERS_FILE, JSON.stringify(users, null, 2));
    console.log('Created users.json with default accounts: admin / Admin@123 and viewer / Viewer@123');
    return users;
  }
  return JSON.parse(fs.readFileSync(USERS_FILE, 'utf8'));
}
const DUMMY_USER = { ...hashPassword('dummy-password'), role: 'viewer' }; // keeps timing equal for unknown users

/* ---------- Simple brute-force protection (per IP) ---------- */
const attempts = new Map(); // ip -> { count, resetAt }
const MAX_FAILS = 10, WINDOW_MS = 5 * 60 * 1000;
function isBlocked(ip) {
  const a = attempts.get(ip);
  if (!a) return false;
  if (a.resetAt < Date.now()) { attempts.delete(ip); return false; }
  return a.count >= MAX_FAILS;
}
function recordFail(ip) {
  const a = attempts.get(ip);
  if (!a || a.resetAt < Date.now()) attempts.set(ip, { count: 1, resetAt: Date.now() + WINDOW_MS });
  else a.count++;
}

/* ---------- JWT helpers ---------- */
const b64url = (buf) => Buffer.from(buf).toString('base64url');

function signJWT(payload) {
  const header = b64url(JSON.stringify({ alg: 'HS256', typ: 'JWT' }));
  const now = Math.floor(Date.now() / 1000);
  const body = b64url(JSON.stringify({ ...payload, iat: now, exp: now + TOKEN_TTL }));
  const sig = crypto.createHmac('sha256', SECRET).update(`${header}.${body}`).digest('base64url');
  return `${header}.${body}.${sig}`;
}

function verifyJWT(token) {
  try {
    const [h, b, s] = token.split('.');
    if (!h || !b || !s) return null;
    const expected = crypto.createHmac('sha256', SECRET).update(`${h}.${b}`).digest();
    const given = Buffer.from(s, 'base64url');
    if (given.length !== expected.length || !crypto.timingSafeEqual(given, expected)) return null;
    const payload = JSON.parse(Buffer.from(b, 'base64url').toString());
    if (payload.exp < Math.floor(Date.now() / 1000)) return null;
    return payload;
  } catch { return null; }
}

/* ---------- Posts storage ---------- */
function loadPosts() {
  try { return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); }
  catch { return []; }
}
const savePosts = (posts) => fs.writeFileSync(DATA_FILE, JSON.stringify(posts, null, 2));

/* ---------- Helpers ---------- */
function send(res, status, data) {
  res.writeHead(status, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 1e5) req.destroy(); });
    req.on('end', () => { try { resolve(raw ? JSON.parse(raw) : {}); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}

function authenticate(req) {
  const h = req.headers['authorization'] || '';
  if (!h.startsWith('Bearer ')) return null;
  return verifyJWT(h.slice(7));
}

const MIME = { '.html': 'text/html', '.css': 'text/css', '.js': 'text/javascript' };

/* ---------- Server ---------- */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  try {
    if (url.pathname.startsWith('/api/')) {
      // POST /api/login  -> { token }
      if (url.pathname === '/api/login' && req.method === 'POST') {
        const ip = req.socket.remoteAddress;
        if (isBlocked(ip)) return send(res, 429, { error: 'Too many failed attempts. Try again in a few minutes.' });

        const { username, password, role } = await readBody(req);
        const name = String(username || '').trim().toLowerCase();
        if (!name || !password) return send(res, 400, { error: 'Enter your username and password.' });
        if (role !== 'admin' && role !== 'viewer') return send(res, 400, { error: 'Invalid role.' });

        const users = loadUsers();
        const account = Object.prototype.hasOwnProperty.call(users, name) ? users[name] : null;
        const passwordOk = checkPassword(String(password), account || DUMMY_USER);

        if (!account || !passwordOk) {
          recordFail(ip);
          return send(res, 401, { error: 'Invalid username or password.' });
        }
        if (account.role !== role) {
          recordFail(ip);
          return send(res, 403, { error: `This account is not allowed to log in as ${role}.` });
        }
        attempts.delete(ip);
        return send(res, 200, { token: signJWT({ username: name, role: account.role }) });
      }

      // Everything below requires a valid JWT
      const user = authenticate(req);
      if (!user) return send(res, 401, { error: 'Invalid or expired token. Please log in again.' });

      // GET /api/posts -> any logged-in user
      if (url.pathname === '/api/posts' && req.method === 'GET') {
        return send(res, 200, loadPosts());
      }

      // POST /api/posts -> admin only
      if (url.pathname === '/api/posts' && req.method === 'POST') {
        if (user.role !== 'admin') return send(res, 403, { error: 'Admins only.' });
        const { text } = await readBody(req);
        const clean = String(text || '').trim();
        if (!clean || clean.length > 500) return send(res, 400, { error: 'Post must be 1-500 characters.' });
        const posts = loadPosts();
        const post = { id: crypto.randomUUID(), text: clean, author: user.username, createdAt: new Date().toISOString() };
        posts.unshift(post);
        savePosts(posts);
        return send(res, 201, post);
      }

      // DELETE /api/posts/:id -> admin only
      const m = url.pathname.match(/^\/api\/posts\/([\w-]+)$/);
      if (m && req.method === 'DELETE') {
        if (user.role !== 'admin') return send(res, 403, { error: 'Admins only.' });
        const posts = loadPosts();
        const next = posts.filter((p) => p.id !== m[1]);
        if (next.length === posts.length) return send(res, 404, { error: 'Post not found.' });
        savePosts(next);
        return send(res, 200, { ok: true });
      }

      return send(res, 404, { error: 'Not found.' });
    }

    // Static files
    const rel = url.pathname === '/' ? 'index.html' : url.pathname.slice(1);
    const file = path.join(PUBLIC_DIR, rel);
    if (!file.startsWith(PUBLIC_DIR) || !fs.existsSync(file) || !fs.statSync(file).isFile()) {
      res.writeHead(404); return res.end('Not found');
    }
    res.writeHead(200, { 'Content-Type': MIME[path.extname(file)] || 'application/octet-stream' });
    fs.createReadStream(file).pipe(res);
  } catch (err) {
    send(res, 400, { error: 'Bad request.' });
  }
});

loadUsers(); // make sure default accounts exist
server.listen(PORT, () => console.log(`Server running at http://localhost:${PORT}`));
