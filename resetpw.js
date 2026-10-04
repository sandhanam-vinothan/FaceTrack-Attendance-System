// Reset any FaceAttend user's password (use when a temp password was lost).
// 1) Stop the server (Ctrl+C)   2) node resetpw.js <email> <newTempPassword>   3) node server.js
// The user will be asked to set their own new password at next login.
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const [, , email, pw] = process.argv;
if (!email || !pw) { console.log('Usage: node resetpw.js <email> <newTempPassword>'); process.exit(1); }
const F = path.join(process.env.DATA_DIR || __dirname, 'data', 'db.json');
let db;
try { db = JSON.parse(fs.readFileSync(F, 'utf8')); } catch { console.log('Cannot read ' + F + ' - run this from the faceattend folder.'); process.exit(1); }
const u = db.users.find((x) => x.email === email.trim().toLowerCase());
if (!u) { console.log('No user with email ' + email + '. Existing users:\n  ' + db.users.map((x) => x.email + ' (' + x.role + ')').join('\n  ')); process.exit(1); }
u.salt = crypto.randomBytes(16).toString('hex');
u.hash = crypto.scryptSync(pw, u.salt, 64).toString('hex');
u.must = true;
fs.writeFileSync(F + '.tmp', JSON.stringify(db)); fs.renameSync(F + '.tmp', F);
console.log('Done. ' + u.email + ' can now log in with: ' + pw + ' (will be asked to change it).');
