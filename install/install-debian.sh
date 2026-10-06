#!/usr/bin/env bash
#
# Install Elenko on Debian / Ubuntu (native Node.js + host CouchDB).
# Requires: Node.js 18.17+ (or 20.3+), CouchDB 3.x reachable from this host.
#
# Examples:
#   sudo ./install/install-debian.sh --install-dir /opt/elenko
#   sudo ./install/install-debian.sh --install-dir /opt/elenko --couchdb-url 'http://admin:secret@127.0.0.1:5984'
#   ./install/install-debian.sh --no-systemd   # deps + .env only (no root)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_INSTALL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
PORT="3000"
COUCHDB_URL="http://admin:admin@127.0.0.1:5984"
COUCHDB_DB="elenko"
CONFIG_DB="elenko_config"
SERVICE_USER="elenko"
SERVICE_NAME="elenko"
DEPLOY_USER=""
INSTALL_SYSTEMD=1
START_SERVICE=1
NODE_MIN_MAJOR=18

# shellcheck source=almalinux-lib.sh
source "${SCRIPT_DIR}/almalinux-lib.sh"

usage() {
  sed -n '2,20p' "$0" | tail -n +2
  cat <<'EOF'

Options:
  --install-dir PATH     Application root (default: parent of install/)
  --port N               PORT in .env (default: 3000)
  --couchdb-url URL      COUCHDB_URL in .env
  --couchdb-db NAME      COUCHDB_DB (default: elenko)
  --config-db NAME       ELENKO_CONFIG_DB (default: elenko_config)
  --service-user NAME    systemd User= (default: elenko)
  --service-name NAME    systemd unit name (default: elenko)
  --deploy-user NAME     Login user allowed to git pull in install dir (group elenko)
  --no-systemd           Skip user + unit file (npm install and .env only)
  --no-start             Do not enable/start systemd unit after install
  -h, --help             Show this help
EOF
}

log_step() { printf '==> %s\n' "$1"; }
log_ok() { printf '    %s\n' "$1"; }

while [[ $# -gt 0 ]]; do
  opt="$(elenko_strip_cr "$1")"
  case "$opt" in
    --install-dir) INSTALL_DIR="$(elenko_strip_cr "$2")"; shift 2 ;;
    --port) PORT="$(elenko_strip_cr "$2")"; shift 2 ;;
    --couchdb-url) COUCHDB_URL="$(elenko_strip_cr "$2")"; shift 2 ;;
    --couchdb-db) COUCHDB_DB="$(elenko_strip_cr "$2")"; shift 2 ;;
    --config-db) CONFIG_DB="$(elenko_strip_cr "$2")"; shift 2 ;;
    --service-user) SERVICE_USER="$(elenko_strip_cr "$2")"; shift 2 ;;
    --service-name) SERVICE_NAME="$(elenko_strip_cr "$2")"; shift 2 ;;
    --deploy-user) DEPLOY_USER="$(elenko_strip_cr "$2")"; shift 2 ;;
    --no-systemd) INSTALL_SYSTEMD=0; shift ;;
    --no-start) START_SERVICE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) printf 'Unknown option: %q\n' "$opt" >&2; usage >&2; exit 1 ;;
  esac
done

INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"

if [[ ! -f "${INSTALL_DIR}/package.json" || ! -f "${INSTALL_DIR}/server.js" ]]; then
  echo "ERROR: ${INSTALL_DIR} does not look like an Elenko install (missing package.json or server.js)." >&2
  exit 1
fi

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node not found in PATH. Install Node.js 18.17+ (see install/README-debian.txt)." >&2
  exit 1
fi

NODE_BIN="$(command -v node)"
NODE_VERSION="$("$NODE_BIN" -v 2>/dev/null || true)"
NODE_MAJOR="${NODE_VERSION#v}"
NODE_MAJOR="${NODE_MAJOR%%.*}"
if [[ -z "$NODE_MAJOR" || "$NODE_MAJOR" -lt "$NODE_MIN_MAJOR" ]]; then
  echo "ERROR: Node.js ${NODE_VERSION:-unknown} found; need ${NODE_MIN_MAJOR}+." >&2
  exit 1
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "ERROR: npm not found in PATH." >&2
  exit 1
fi

if [[ "$INSTALL_SYSTEMD" -eq 1 && "$(id -u)" -ne 0 ]]; then
  echo "ERROR: systemd install requires root. Re-run with sudo or pass --no-systemd." >&2
  exit 1
fi

echo ""
echo "Elenko Debian install"
echo "Install directory: ${INSTALL_DIR}"
echo ""

elenko_chmod_install_scripts "$SCRIPT_DIR"

log_step "Checking Node.js"
log_ok "Node.js ${NODE_VERSION} at ${NODE_BIN}"

log_step "Installing npm dependencies (production)"
if [[ ! -f "${INSTALL_DIR}/package-lock.json" ]]; then
  echo "ERROR: package-lock.json not found in ${INSTALL_DIR}." >&2
  exit 1
fi
(
  cd "$INSTALL_DIR"
  npm ci --omit=dev
)
log_ok "Dependencies installed"

log_step "Creating data directories"
mkdir -p "${INSTALL_DIR}/logs" "${INSTALL_DIR}/io" "${INSTALL_DIR}/public/backups"
log_ok "logs/, io/, public/backups/ ready"

log_step "Environment file"
ENV_FILE="${INSTALL_DIR}/.env"
ENV_EXAMPLE="${SCRIPT_DIR}/.env.example"
if [[ -f "$ENV_FILE" ]]; then
  log_ok ".env already exists (left unchanged): ${ENV_FILE}"
else
  if [[ ! -f "$ENV_EXAMPLE" ]]; then
    echo "ERROR: Missing template ${ENV_EXAMPLE}" >&2
    exit 1
  fi
  SESSION_SECRET=""
  if command -v openssl >/dev/null 2>&1; then
    SESSION_SECRET="$(openssl rand -base64 32 | tr -d '\n')"
  else
    SESSION_SECRET="$(head -c 32 /dev/urandom | base64 | tr -d '\n')"
  fi
  cp "$ENV_EXAMPLE" "$ENV_FILE"
  sed -i \
    -e "s|^PORT=.*|PORT=${PORT}|" \
    -e "s|^COUCHDB_URL=.*|COUCHDB_URL=${COUCHDB_URL}|" \
    -e "s|^COUCHDB_DB=.*|COUCHDB_DB=${COUCHDB_DB}|" \
    -e "s|^ELENKO_CONFIG_DB=.*|ELENKO_CONFIG_DB=${CONFIG_DB}|" \
    -e "s|^SESSION_SECRET=.*|SESSION_SECRET=${SESSION_SECRET}|" \
    "$ENV_FILE"
  if ! grep -q '^SESSION_SECRET=' "$ENV_FILE"; then
    printf 'SESSION_SECRET=%s\n' "$SESSION_SECRET" >>"$ENV_FILE"
  fi
  log_ok "Created .env from template: ${ENV_FILE}"
fi

if [[ "$INSTALL_SYSTEMD" -eq 1 ]]; then
  log_step "System user and permissions"
  if ! id "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --home-dir "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
    log_ok "Created system user ${SERVICE_USER}"
  else
    log_ok "User ${SERVICE_USER} already exists"
  fi
  elenko_apply_service_tree_permissions "$INSTALL_DIR" "$SERVICE_USER" "$DEPLOY_USER"
  log_ok "Ownership set to ${SERVICE_USER}:${SERVICE_USER}"

  log_step "systemd unit ${SERVICE_NAME}.service"
  UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
  cat >"$UNIT_PATH" <<EOF
[Unit]
Description=Elenko web application
Documentation=file://${INSTALL_DIR}/README.md
After=network-online.target couchdb.service
Wants=network-online.target

[Service]
Type=simple
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${INSTALL_DIR}
Environment=NODE_ENV=production
EnvironmentFile=-${ENV_FILE}
ExecStart=${NODE_BIN} server.js
Restart=on-failure
RestartSec=5
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF
  log_ok "Wrote ${UNIT_PATH}"

  log_step "Enabling systemd service"
  systemctl daemon-reload
  systemctl enable "${SERVICE_NAME}.service"
  if [[ "$START_SERVICE" -eq 1 ]]; then
    systemctl restart "${SERVICE_NAME}.service"
    log_ok "Started ${SERVICE_NAME}.service"
  else
    log_ok "Enabled ${SERVICE_NAME}.service (not started; use --no-start)"
  fi
fi

echo ""
echo "Install complete."
echo ""
echo "Prerequisites (on this host):"
echo "  - CouchDB 3.x listening (default ${COUCHDB_URL})"
echo "  - If npm ci failed on sharp: sudo apt install -y build-essential python3"
echo ""
echo "Next steps:"
if [[ "$INSTALL_SYSTEMD" -eq 1 ]]; then
  echo "  1. Ensure CouchDB is running"
  echo "  2. Open http://localhost:${PORT}/setup to finish CouchDB bootstrap (first run)"
  echo "  3. Service: systemctl status ${SERVICE_NAME}"
  echo "     Logs:     journalctl -u ${SERVICE_NAME} -f"
else
  echo "  1. Start CouchDB"
  echo "  2. cd \"${INSTALL_DIR}\" && npm start"
  echo "  3. Open http://localhost:${PORT}/setup"
fi
echo ""
echo "Upgrade later (keep .env, couchdb.bootstrap.json, logs/, io/):"
echo "  sudo bash install/upgrade-debian.sh --install-dir \"${INSTALL_DIR}\""
echo ""
