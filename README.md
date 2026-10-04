# FaceAttend
Run locally: `node server.js` -> http://localhost:3100 (Node 18+, no npm install needed).
First admin: admin@college.edu / Admin@123 (or ADMIN_EMAIL / ADMIN_PASSWORD env vars). You must change it on first login.
Deploy: push to GitHub -> Render -> New Blueprint. Free Render disks are temporary: data resets on redeploy/restart.
For permanent data attach a Render persistent disk and set DATA_DIR to its mount path (e.g. /var/data).
