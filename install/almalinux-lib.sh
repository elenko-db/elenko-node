#!/usr/bin/env bash
# Shared helpers for install/upgrade-almalinux.sh (source, do not run directly).

elenko_chmod_install_scripts() {
  local script_dir="$1"
  if [[ ! -d "$script_dir" ]]; then
    return 0
  fi
  chmod 755 "${script_dir}/install-almalinux.sh" "${script_dir}/upgrade-almalinux.sh" 2>/dev/null || true
  for f in "${script_dir}"/*.sh; do
    [[ -f "$f" ]] && chmod 755 "$f"
  done
}

elenko_systemd_service_user() {
  local service_name="$1"
  local default_user="$2"
  local unit="/etc/systemd/system/${service_name}.service"
  if [[ -f "$unit" ]]; then
    local u
    u="$(grep -E '^User=' "$unit" | tail -1 | cut -d= -f2- | tr -d ' ')"
    if [[ -n "$u" ]]; then
      printf '%s' "$u"
      return 0
    fi
  fi
  printf '%s' "$default_user"
}

elenko_run_npm_ci_as_user() {
  local install_dir="$1"
  local run_as="$2"
  if [[ "$(id -u)" -eq 0 ]]; then
    if ! id "$run_as" >/dev/null 2>&1; then
      echo "ERROR: user ${run_as} does not exist." >&2
      return 1
    fi
    runuser -u "$run_as" -s /bin/bash -c "cd $(printf '%q' "$install_dir") && npm ci --omit=dev"
  else
    (cd "$install_dir" && npm ci --omit=dev)
  fi
}

# Service-owned tree; optional login user in group for git pull without sudo.
elenko_apply_service_tree_permissions() {
  local install_dir="$1"
  local service_user="$2"
  local deploy_user="${3:-}"

  chown -R "${service_user}:${service_user}" "$install_dir"
  if [[ -n "$deploy_user" ]] && id "$deploy_user" >/dev/null 2>&1; then
    usermod -aG "$service_user" "$deploy_user" 2>/dev/null || true
    chmod -R u=rwX,g=rwX,o= "$install_dir"
    find "$install_dir" -type d -exec chmod g+s {} +
    log_ok "Deploy user ${deploy_user} added to group ${service_user} (git pull without sudo after re-login)"
  fi
  if [[ -f "${install_dir}/.env" ]]; then
    chown "${service_user}:${service_user}" "${install_dir}/.env"
    chmod 600 "${install_dir}/.env"
  fi
}
