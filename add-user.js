// Usage: node add-user.js <username> <password> <admin|viewer>
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const [name, password, role] = process.argv.slice(2);
if (!name || !password || !['admin', 'viewer'].includes(role)) {
  console.log('Usage: node add-user.js <username> <password> <admin|viewer>');
  process.exit(1);
}
if (password.length < 6) { console.log('Password must be at least 6 characters.'); process.exit(1); }

const file = path.join(__dirname, 'users.json');
const users = fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, 'utf8')) : {};
const salt = crypto.randomBytes(16).toString('hex');
const hash = crypto.scryptSync(password, salt, 64).toString('hex');
users[name.trim().toLowerCase()] = { salt, hash, role };
fs.writeFileSync(file, JSON.stringify(users, null, 2));
console.log(`Saved ${role} account "${name.trim().toLowerCase()}". Restart is not required.`);
