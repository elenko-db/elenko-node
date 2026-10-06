Elenko – Debian / Ubuntu install (no Docker)
============================================

Tested target: Debian 13 (trixie) amd64 with host CouchDB and Node.js 20+.

Prerequisites (install separately)
----------------------------------
- Node.js 18.17+ or 20.3+ and npm (sharp needs a recent 18.x patch)
- CouchDB 3.x on this host (default http://127.0.0.1:5984, user admin)

If npm ci fails building sharp:
  sudo apt install -y build-essential python3

What to put in /opt/elenko
---------------------------
Copy the application source tree (not node_modules). Easiest on the server:

  sudo git clone https://github.com/elenko-db/elenko-node.git /opt/elenko

Or from your dev machine (PowerShell example):

  scp -r package.json package-lock.json server.js *Worker.js public install README.md user@host:/opt/elenko/

Required at minimum:
  package.json, package-lock.json
  server.js, apiWorker.js, flowWorker.js, federationWorker.js, scriptWorker.js, timerWorker.js
  public/
  install/          (.env.example and install-debian.sh)

Recommended (full repo):
  examples/, docs/, ressources/

Do NOT copy (created on the server):
  node_modules/     → npm ci in install script
  .env              → created from install/.env.example
  logs/, io/        → created empty (io/ holds optional import configs)
  couchdb.bootstrap.json → created by /setup in the browser

Do NOT need for native CouchDB install:
  Dockerfile, docker-compose*.yml, couchdb/ (Docker-only snippets)

Install
-------
  cd /opt/elenko
  sudo bash install/install-debian.sh --install-dir /opt/elenko

CouchDB password (use single quotes if special characters):
  sudo bash install/install-debian.sh \
    --install-dir /opt/elenko \
    --couchdb-url 'http://admin:YOUR_PASSWORD@127.0.0.1:5984'

Allow your login user to git pull without sudo (log out/in after):
  sudo bash install/install-debian.sh --install-dir /opt/elenko --deploy-user YOUR_USER

Deps + .env only (no systemd):
  bash install/install-debian.sh --no-systemd --install-dir /opt/elenko

First-time application setup
----------------------------
1. Ensure CouchDB is running (systemctl status couchdb).
2. Open http://<host>:3000/setup in a browser.
3. Enter the CouchDB admin password to create couchdb.bootstrap.json and databases.
4. Log in to Elenko (default app user admin / admin) and change the app password.

systemd
-------
  sudo systemctl status elenko
  sudo journalctl -u elenko -f
  sudo systemctl restart elenko

The service runs as user "elenko" and reads EnvironmentFile from .env in the install directory.

Firewall (if ufw is enabled)
------------------------------
  sudo ufw allow 3000/tcp

Production: put nginx or Caddy in front for HTTPS instead of exposing port 3000 publicly.

Upgrade
-------
1. Update files in /opt/elenko (git pull or rsync). Keep:
   - .env
   - couchdb.bootstrap.json
   - logs/
   - io/
2. sudo bash install/upgrade-debian.sh --install-dir /opt/elenko

Configuration
-------------
Edit .env in the install directory. See install/.env.example for variables.
