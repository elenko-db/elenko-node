#!/usr/bin/env bash
#
# Upgrade Elenko after updating application files in the install directory.
#
# Example:
#   sudo bash install/upgrade-debian.sh --install-dir /opt/elenko
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_INSTALL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
SERVICE_NAME="elenko"
SERVICE_USER="elenko"
RESTART_SERVICE=1

# shellcheck source=almalinux-lib.sh
source "${SCRIPT_DIR}/almalinux-lib.sh"

usage() {
  cat <<'EOF'
Usage: upgrade-debian.sh [options]

Run with sudo when a systemd service is installed (recommended).

Options:
  --install-dir PATH   Application root (default: parent of install/)
  --service-name NAME  systemd unit (default: elenko)
  --service-user NAME  User for npm ci (default: read from unit, else elenko)
  --no-restart         Skip systemctl restart (only npm ci)
  -h, --help           Show help
EOF
}

log_step() { printf '==> %s\n' "$1"; }
log_ok() { printf '    %s\n' "$1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --service-name) SERVICE_NAME="$2"; shift 2 ;;
    --service-user) SERVICE_USER="$2"; shift 2 ;;
    --no-restart) RESTART_SERVICE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"

elenko_chmod_install_scripts "$SCRIPT_DIR"

if [[ ! -f "${INSTALL_DIR}/package-lock.json" ]]; then
  echo "ERROR: package-lock.json not found in ${INSTALL_DIR}." >&2
  exit 1
fi

UNIT="${SERVICE_NAME}.service"
UNIT_PATH="/etc/systemd/system/${UNIT}"
HAS_SYSTEMD=0
if [[ -f "$UNIT_PATH" ]] || systemctl list-unit-files "${UNIT}" >/dev/null 2>&1; then
  HAS_SYSTEMD=1
fi

if [[ "$HAS_SYSTEMD" -eq 1 ]]; then
  SERVICE_USER="$(elenko_systemd_service_user "$SERVICE_NAME" "$SERVICE_USER")"
fi

echo ""
echo "Elenko Debian upgrade"
echo "Install directory: ${INSTALL_DIR}"
if [[ "$HAS_SYSTEMD" -eq 1 ]]; then
  echo "Service user: ${SERVICE_USER}"
fi
echo ""

if [[ "$HAS_SYSTEMD" -eq 1 ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: stopping/starting ${UNIT} requires root. Re-run:" >&2
    echo "  sudo bash ${SCRIPT_DIR}/upgrade-debian.sh --install-dir $(printf '%q' "$INSTALL_DIR")" >&2
    exit 1
  fi
  log_step "Stopping ${UNIT}"
  systemctl stop "${UNIT}" || true
fi

log_step "Refreshing npm dependencies (as ${SERVICE_USER})"
elenko_run_npm_ci_as_user "$INSTALL_DIR" "$SERVICE_USER"

if [[ "$(id -u)" -eq 0 && "$HAS_SYSTEMD" -eq 1 ]]; then
  log_step "Fixing ownership and install script permissions"
  chown -R "${SERVICE_USER}:${SERVICE_USER}" "$INSTALL_DIR"
  if [[ -f "${INSTALL_DIR}/.env" ]]; then
    chmod 600 "${INSTALL_DIR}/.env"
  fi
  elenko_chmod_install_scripts "$SCRIPT_DIR"
  log_ok "Tree owned by ${SERVICE_USER}; install/*.sh executable"
fi

if [[ "$HAS_SYSTEMD" -eq 1 && "$RESTART_SERVICE" -eq 1 ]]; then
  log_step "Starting ${UNIT}"
  systemctl start "${UNIT}"
  systemctl status "${UNIT}" --no-pager -l || true
fi

echo ""
echo "Upgrade complete."
if [[ "$HAS_SYSTEMD" -eq 0 ]]; then
  echo "Restart Elenko manually if it was running (npm start)."
fi
echo ""
