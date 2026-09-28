
| Username | Password   | Role   |
|----------|------------|--------|
| admin    | Admin@123  | admin  |
| viewer   | Viewer@123 | viewer |

Change these or add more:  `node add-user.js <username> <password> <admin|viewer>`
(passwords are stored as salted scrypt hashes, never in plain text; 10 failed
logins from one IP are blocked for 5 minutes).

- Set your own secret:  JWT_SECRET=your-long-random-string node server.js
- Delete users.json to reset the default accounts.
- For production, serve over HTTPS.
