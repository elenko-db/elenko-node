#!/usr/bin/env bash
#
# Upgrade Elenko after updating application files in the install directory.
#
# Example:
#   sudo ./install/upgrade-almalinux.sh
#   sudo ./install/upgrade-almalinux.sh --install-dir /opt/elenko --service-name elenko
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEFAULT_INSTALL_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

INSTALL_DIR="${DEFAULT_INSTALL_DIR}"
SERVICE_NAME="elenko"
RESTART_SERVICE=1

usage() {
  cat <<'EOF'
Usage: upgrade-almalinux.sh [options]

Options:
  --install-dir PATH   Application root (default: parent of install/)
  --service-name NAME  systemd unit (default: elenko)
  --no-restart         Skip systemctl restart (only npm ci)
  -h, --help           Show help
EOF
}

log_step() { printf '==> %s\n' "$1"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-dir) INSTALL_DIR="$2"; shift 2 ;;
    --service-name) SERVICE_NAME="$2"; shift 2 ;;
    --no-restart) RESTART_SERVICE=0; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

INSTALL_DIR="$(cd "$INSTALL_DIR" && pwd)"

if [[ ! -f "${INSTALL_DIR}/package-lock.json" ]]; then
  echo "ERROR: package-lock.json not found in ${INSTALL_DIR}." >&2
  exit 1
fi

UNIT="${SERVICE_NAME}.service"
HAS_SYSTEMD=0
if systemctl list-unit-files "${UNIT}" >/dev/null 2>&1; then
  HAS_SYSTEMD=1
fi

echo ""
echo "Elenko AlmaLinux upgrade"
echo "Install directory: ${INSTALL_DIR}"
echo ""

if [[ "$HAS_SYSTEMD" -eq 1 ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "ERROR: stopping/starting ${UNIT} requires root. Re-run with sudo." >&2
    exit 1
  fi
  log_step "Stopping ${UNIT}"
  systemctl stop "${UNIT}" || true
fi

log_step "Refreshing npm dependencies"
(
  cd "$INSTALL_DIR"
  npm ci --omit=dev
)

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
