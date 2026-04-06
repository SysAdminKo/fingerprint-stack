#!/usr/bin/env bash
set -euo pipefail

#
# Automate "replace domain completely" for the fingerprint stack.
#
# What it does (as root via sudo):
# - stops fp-h2edge (frees :80 for certbot standalone)
# - obtains/renews a Let's Encrypt cert for the new domain
# - writes env files:
#     /etc/fp/fp-h2edge.env   (H2EDGE_CERT/H2EDGE_KEY)
#     /etc/fp/fp-upstream.env (FP_PUBLIC_HOST)
# - installs/updates systemd drop-ins to load those env files
# - reloads systemd and restarts fp-h2edge + fp-upstream
#
# Requirements:
# - DNS A/AAAA for the domain points to this server
# - inbound :80 reachable from the Internet for HTTP-01
# - certbot installed and working
#

usage() {
  cat <<'EOF'
Usage:
  deploy/set-domain.sh <domain> [--email you@example.com]

Env:
  CERTBOT_EMAIL          Alternative to --email (required for non-interactive)
  FP_ENV_DIR             Where to store env files (default: /etc/fp)
  FP_H2EDGE_ENV_FILE     Path to fp-h2edge env file (default: $FP_ENV_DIR/fp-h2edge.env)
  FP_UPSTREAM_ENV_FILE   Path to fp-upstream env file (default: $FP_ENV_DIR/fp-upstream.env)
  FP_H2EDGE_SERVICE      systemd service name (default: fp-h2edge)
  FP_UPSTREAM_SERVICE    systemd service name (default: fp-upstream)
  CERTBOT_BIN            certbot path (default: certbot)

Notes:
  - This uses certbot --standalone (HTTP-01), so it stops fp-h2edge temporarily.
  - Certificate paths are set to /etc/letsencrypt/live/<domain>/{fullchain.pem,privkey.pem}.
EOF
}

die() { echo "error: $*" >&2; exit 1; }

domain="${1:-}"
shift || true
[[ -n "${domain}" ]] || { usage; exit 2; }

email=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --email)
      shift || true
      email="${1:-}"
      [[ -n "${email}" ]] || die "--email requires a value"
      shift || true
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown arg: $1"
      ;;
  esac
done

if [[ -z "${email}" ]]; then
  email="${CERTBOT_EMAIL:-}"
fi
[[ -n "${email}" ]] || die "email is required (use --email or CERTBOT_EMAIL)"

fp_env_dir="${FP_ENV_DIR:-/etc/fp}"
fp_h2edge_env="${FP_H2EDGE_ENV_FILE:-$fp_env_dir/fp-h2edge.env}"
fp_upstream_env="${FP_UPSTREAM_ENV_FILE:-$fp_env_dir/fp-upstream.env}"

svc_h2edge="${FP_H2EDGE_SERVICE:-fp-h2edge}"
svc_upstream="${FP_UPSTREAM_SERVICE:-fp-upstream}"
certbot_bin="${CERTBOT_BIN:-certbot}"

cert_dir="/etc/letsencrypt/live/${domain}"
cert_file="${cert_dir}/fullchain.pem"
key_file="${cert_dir}/privkey.pem"

if [[ "${EUID}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    exec sudo -E bash "$0" "$domain" --email "$email"
  fi
  die "must run as root (or have sudo)"
fi

mkdir -p "${fp_env_dir}"
chmod 700 "${fp_env_dir}"

echo "[1/5] Stopping ${svc_h2edge} (free :80 for certbot)..."
systemctl stop "${svc_h2edge}" || true

echo "[2/5] Issuing/renewing certificate for ${domain}..."
"${certbot_bin}" certonly \
  --standalone \
  --non-interactive \
  --agree-tos \
  --email "${email}" \
  -d "${domain}"

[[ -f "${cert_file}" ]] || die "cert not found at ${cert_file}"
[[ -f "${key_file}" ]] || die "key not found at ${key_file}"

echo "[3/5] Writing env files..."
umask 077
cat > "${fp_h2edge_env}" <<EOF
# Managed by deploy/set-domain.sh
H2EDGE_CERT=${cert_file}
H2EDGE_KEY=${key_file}
EOF

cat > "${fp_upstream_env}" <<EOF
# Managed by deploy/set-domain.sh
FP_PUBLIC_HOST=${domain}
EOF

echo "[4/5] Installing systemd drop-ins..."
mkdir -p "/etc/systemd/system/${svc_h2edge}.service.d"
mkdir -p "/etc/systemd/system/${svc_upstream}.service.d"

cat > "/etc/systemd/system/${svc_h2edge}.service.d/10-env.conf" <<EOF
# Managed by deploy/set-domain.sh
[Service]
EnvironmentFile=${fp_h2edge_env}
EOF

cat > "/etc/systemd/system/${svc_upstream}.service.d/10-env.conf" <<EOF
# Managed by deploy/set-domain.sh
[Service]
EnvironmentFile=${fp_upstream_env}
EOF

systemctl daemon-reload

echo "[5/5] Restarting services..."
systemctl restart "${svc_upstream}"
systemctl restart "${svc_h2edge}"

echo "Done."
echo "Domain: ${domain}"
echo "Cert:   ${cert_file}"
echo "Key:    ${key_file}"

