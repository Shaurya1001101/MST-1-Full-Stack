(() => {
  const TOKEN_KEY = 'jwt_token';

  const $ = (id) => document.getElementById(id);
  const loginSection = $('login-section');
  const dashSection = $('dashboard-section');
  const usernameInput = $('username');
  const passwordInput = $('password');
  const loginError = $('login-error');
  const dashError = $('dash-error');
  const welcome = $('welcome');
  const adminPanel = $('admin-panel');
  const readonlyNote = $('readonly-note');
  const postList = $('post-list');
  const emptyMsg = $('empty');
  const postText = $('post-text');

  let currentUser = null;
  let pollTimer = null;

  /* ---------- JWT helpers (client side: only to read the display info) ---------- */
  function decodeToken(token) {
    try {
      const b64 = token.split('.')[1].replace(/-/g, '+').replace(/_/g, '/');
      const json = decodeURIComponent(
        atob(b64).split('').map((c) => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
      );
      const payload = JSON.parse(json);
      if (payload.exp * 1000 < Date.now()) return null;
      return payload;
    } catch { return null; }
  }

  const getToken = () => sessionStorage.getItem(TOKEN_KEY);

  // fetch wrapper that attaches the JWT and handles expired tokens
  async function api(url, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...(options.headers || {}) };
    const token = getToken();
    if (token) headers['Authorization'] = 'Bearer ' + token;
    const res = await fetch(url, { ...options, headers });
    const data = await res.json().catch(() => ({}));
    if (res.status === 401 && token) { logout('Session expired. Please log in again.'); throw new Error('unauthorized'); }
    if (!res.ok) throw new Error(data.error || 'Something went wrong.');
    return data;
  }

  /* ---------- Views ---------- */
  function showLogin(message = '') {
    dashSection.classList.add('hidden');
    loginSection.classList.remove('hidden');
    loginError.textContent = message;
    usernameInput.value = '';
    passwordInput.value = '';
    usernameInput.focus();
  }

  function showDashboard(user) {
    currentUser = user;
    loginSection.classList.add('hidden');
    dashSection.classList.remove('hidden');
    dashError.textContent = '';
    welcome.textContent = `Welcome, ${user.username} (${user.role})`;

    const isAdmin = user.role === 'admin';
    adminPanel.classList.toggle('hidden', !isAdmin);
    readonlyNote.classList.toggle('hidden', isAdmin);

    loadPosts();
    clearInterval(pollTimer);
    pollTimer = setInterval(loadPosts, 5000); // keeps posts in sync
  }

  function renderPosts(posts) {
    postList.innerHTML = '';
    emptyMsg.classList.toggle('hidden', posts.length > 0);

    posts.forEach((post) => {
      const li = document.createElement('li');

      const body = document.createElement('div');
      body.className = 'post-body';
      const text = document.createElement('span');
      text.textContent = post.text; // textContent prevents XSS
      const meta = document.createElement('span');
      meta.className = 'post-meta';
      meta.textContent = `by ${post.author} · ${new Date(post.createdAt).toLocaleString()}`;
      body.append(text, meta);
      li.appendChild(body);

      if (currentUser.role === 'admin') {
        const del = document.createElement('button');
        del.className = 'btn danger';
        del.textContent = 'Delete Post';
        del.addEventListener('click', () => deletePost(post.id));
        li.appendChild(del);
      }
      postList.appendChild(li);
    });
  }

  /* ---------- Actions ---------- */
  async function login(role) {
    const username = usernameInput.value.trim();
    const password = passwordInput.value;
    if (!username || !password) { loginError.textContent = 'Please enter your username and password.'; return; }
    try {
      const { token } = await api('/api/login', { method: 'POST', body: JSON.stringify({ username, password, role }) });
      passwordInput.value = '';
      sessionStorage.setItem(TOKEN_KEY, token);
      loginError.textContent = '';
      showDashboard(decodeToken(token));
    } catch (e) { loginError.textContent = e.message; }
  }

  function logout(message = '') {
    sessionStorage.removeItem(TOKEN_KEY);
    clearInterval(pollTimer);
    currentUser = null;
    showLogin(message);
  }

  async function loadPosts() {
    try { renderPosts(await api('/api/posts')); }
    catch (e) { if (e.message !== 'unauthorized') dashError.textContent = e.message; }
  }

  async function addPost() {
    const text = postText.value.trim();
    if (!text) { dashError.textContent = 'Write something first.'; return; }
    try {
      await api('/api/posts', { method: 'POST', body: JSON.stringify({ text }) });
      postText.value = '';
      dashError.textContent = '';
      loadPosts();
    } catch (e) { if (e.message !== 'unauthorized') dashError.textContent = e.message; }
  }

  async function deletePost(id) {
    try {
      await api('/api/posts/' + id, { method: 'DELETE' });
      dashError.textContent = '';
      loadPosts();
    } catch (e) { if (e.message !== 'unauthorized') dashError.textContent = e.message; }
  }

  /* ---------- Events ---------- */
  $('login-admin').addEventListener('click', () => login('admin'));
  $('login-viewer').addEventListener('click', () => login('viewer'));
  $('logout').addEventListener('click', () => logout());
  $('add-post').addEventListener('click', addPost);
  postText.addEventListener('keydown', (e) => { if (e.key === 'Enter') addPost(); });
  usernameInput.addEventListener('keydown', (e) => { if (e.key === 'Enter') passwordInput.focus(); });

  /* ---------- Restore session on refresh ---------- */
  const saved = getToken();
  const user = saved && decodeToken(saved);
  if (user) showDashboard(user); else { sessionStorage.removeItem(TOKEN_KEY); showLogin(); }
})();
