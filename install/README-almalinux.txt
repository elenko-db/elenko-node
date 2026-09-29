Elenko – AlmaLinux / RHEL-family install (no Docker)
====================================================

Prerequisites (install separately)
----------------------------------
- AlmaLinux 10 (or compatible RHEL-family) with Node.js 18+ and npm
- CouchDB 3.x on this host (default http://127.0.0.1:5984, user admin)

Optional if npm install fails on the sharp package:
  sudo dnf install -y gcc-c++ make python3

Install from a git clone
------------------------
  cd /opt
  sudo git clone https://github.com/elenko-db/elenko-node.git elenko
  cd elenko
  sudo ./install/install-almalinux.sh --install-dir /opt/elenko

  Allow your login user to git pull without chmod 770 (log out/in after install):
  sudo ./install/install-almalinux.sh --install-dir /opt/elenko --deploy-user YOUR_USER

Custom CouchDB URL (password with special characters: use single quotes):
  sudo ./install/install-almalinux.sh \
    --install-dir /opt/elenko \
    --couchdb-url 'http://admin:YOUR_PASSWORD@127.0.0.1:5984'

Deps + .env only (no systemd, no root):
  ./install/install-almalinux.sh --no-systemd

First-time application setup
----------------------------
1. Ensure CouchDB is running.
2. Open http://<host>:3000/setup in a browser.
3. Enter the CouchDB admin password to create couchdb.bootstrap.json and databases.
4. Log in to Elenko (default app user admin / admin) and change the app password.

systemd
-------
  sudo systemctl status elenko
  sudo journalctl -u elenko -f
  sudo systemctl restart elenko

The service runs as user "elenko" and reads EnvironmentFile from .env in the install directory.

Firewall (if needed)
--------------------
  sudo firewall-cmd --permanent --add-port=3000/tcp
  sudo firewall-cmd --reload

Production: put nginx or Caddy in front for HTTPS instead of exposing port 3000 publicly.

Upgrade
-------
1. Update application files (git pull or copy tree). Keep:
   - .env
   - couchdb.bootstrap.json
   - logs/
   - io/
   If the tree is owned by user "elenko", either:
   - git pull as root: sudo git -C /opt/elenko pull
   - or install once with --deploy-user YOUR_USER (see above), then git pull as that user
2. Run (use bash if execute bit missing after git pull on Windows):
     sudo bash install/upgrade-almalinux.sh --install-dir /opt/elenko
   Do not chmod 770 manually; the upgrade script runs npm as the service user and fixes ownership.

Configuration
-------------
Edit .env in the install directory. See install/.env.example for variables.
