#!/usr/bin/env bash
set -euo pipefail

# Fully automated installer for fingerprint-stack on a fresh server.
# - Installs OS packages (dnf/apt)
# - Installs Go (if needed) to match go.mod (default: 1.25.0)
# - Builds and installs binaries to /usr/local/bin
# - Installs and enables systemd services: fp-h2edge, fp-upstream, fp-netagent, p0f
# - Optionally obtains/renews Let's Encrypt cert for a domain (certbot standalone)
# - Supports both CLI flags and interactive prompts

usage() {
  cat <<'EOF'
Usage:
  deploy/install.sh [options]

Options:
  --domain <name>              Public domain (for cert + UI host)
  --email <addr>               Let's Encrypt email (required if --domain is set)
  --repo-dir <path>            Path to repo (default: auto-detect from script location)
  --repo-url <url>             Git URL to clone from (default: https://github.com/SysAdminKo/fingerprint-stack.git)
  --install-dir <path>         Where to clone repo when using --repo-url (default: /opt/fingerprint-stack)
  --update <yes|no>            If install-dir exists, git pull (default: no)
  --ref <rev>                  Git ref to checkout (branch/tag/commit). Default: repo default branch
  --depth <n>                  Shallow clone depth (only for new clones; default: full)
  --go-version <ver>           Go version to install if needed (default: 1.25.0)
  --install-go <yes|no>        Force Go install (default: auto)
  --issue-cert <yes|no>        Run certbot to issue cert (default: yes if --domain set)

  --h2edge-listen <addr>       Default: 0.0.0.0:443
  --h2edge-http-listen <addr>  Default: 0.0.0.0:80
  --upstream-listen <addr>     Default: 127.0.0.1:9000
  --ttl-api <url>              Default: http://127.0.0.1:9100
  --trusted-proxy-cidrs <cidrs> Default: 127.0.0.1/8,::1/128

  --pcap-iface <iface>         Default: any
  --pcap-tcpdump <path>        Default: /usr/sbin/tcpdump
  --pcap-save-dir <path>       Default: /var/lib/fp/pcap

  --dry-run                    Print actions and exit without changes
  --non-interactive            Fail instead of prompting
  -h, --help                   Show help

Examples:
  # Fully automatic (recommended)
  sudo ./deploy/install.sh --domain example.com --email you@example.com

  # Install on a fresh server by cloning repo
  sudo ./deploy/install.sh --repo-url https://github.com/you/fingerprint-stack.git --domain example.com --email you@example.com

  # Install services only, no cert
  sudo ./deploy/install.sh --issue-cert no
EOF
}

die() { echo "error: $*" >&2; exit 1; }
say() { echo "==> $*"; }

print_kv() { printf "  - %-22s %s\n" "$1" "$2"; }

is_yes() {
  case "${1,,}" in
    y|yes|true|1) return 0 ;;
    n|no|false|0) return 1 ;;
    *) return 1 ;;
  esac
}

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      exec sudo -E bash "$0" "$@"
    fi
    die "must run as root (or have sudo)"
  fi
}

print_dry_run_plan() {
  local pkg_mgr
  pkg_mgr="$(detect_pkg_mgr)"

  echo
  say "DRY RUN (no changes will be made)"
  echo
  echo "Config:"
  print_kv "repo_dir" "${REPO_DIR}"
  print_kv "repo_url" "${REPO_URL:-<none>}"
  print_kv "install_dir" "${INSTALL_DIR:-<n/a>}"
  print_kv "update" "${UPDATE_REPO}"
  print_kv "ref" "${REF:-<default origin/HEAD>}"
  print_kv "depth" "${DEPTH:-<full>}"
  print_kv "pkg_mgr" "${pkg_mgr}"
  print_kv "go_version" "${GO_VERSION}"
  print_kv "install_go" "${INSTALL_GO}"
  print_kv "issue_cert" "${ISSUE_CERT}"
  print_kv "domain" "${DOMAIN:-<none>}"
  print_kv "email" "${EMAIL:-<none>}"
  echo
  echo "Runtime settings:"
  print_kv "h2edge_listen" "${H2EDGE_LISTEN}"
  print_kv "h2edge_http" "${H2EDGE_HTTP_LISTEN}"
  print_kv "upstream_listen" "${UPSTREAM_LISTEN}"
  print_kv "ttl_api" "${TTL_API}"
  print_kv "trusted_proxy" "${TRUSTED_PROXY_CIDRS}"
  print_kv "pcap_iface" "${PCAP_IFACE}"
  print_kv "pcap_tcpdump" "${PCAP_TCPDUMP}"
  print_kv "pcap_save_dir" "${PCAP_SAVE_DIR}"
  echo
  echo "Would perform:"
  echo "  1) Install packages (certbot, tcpdump, p0f, bcc/eBPF toolchain, etc.) via ${pkg_mgr}"
  if [[ -n "${REPO_URL}" ]]; then
    echo "  2) Clone/update repo:"
    echo "     - git clone ${REPO_URL} ${INSTALL_DIR}"
    if [[ -n "${DEPTH}" ]]; then
      echo "       (with --depth ${DEPTH})"
    fi
    echo "     - checkout ref: ${REF:-<origin/HEAD default>}"
  else
    echo "  2) Use repo directory: ${REPO_DIR}"
  fi
  echo "  3) Ensure Go (mode=${INSTALL_GO}, version=${GO_VERSION})"
  echo "  4) Build/install binaries:"
  echo "     - (cd fp/h2edge && go build) -> /usr/local/bin/fp-h2edge"
  echo "     - (cd fp/upstream && go build) -> /usr/local/bin/fp-upstream"
  echo "     - fp/netagent/fp_netagent.py -> /usr/local/bin/fp-netagent"
  if is_yes "${ISSUE_CERT}"; then
    echo "  5) Issue/renew cert:"
    echo "     - systemctl stop fp-h2edge"
    echo "     - certbot certonly --standalone -d ${DOMAIN} --email ${EMAIL}"
    echo "     - use /etc/letsencrypt/live/${DOMAIN}/{fullchain.pem,privkey.pem}"
  else
    echo "  5) Skip cert issuance"
  fi
  echo "  6) Write env files:"
  echo "     - /etc/fp/fp-upstream.env"
  echo "     - /etc/fp/fp-h2edge.env"
  echo "  7) Install/enable systemd units:"
  echo "     - /etc/systemd/system/{fp-upstream,fp-h2edge,fp-netagent,p0f}.service"
  echo "     - systemctl enable --now p0f fp-netagent fp-upstream fp-h2edge"
  echo
}

prompt() {
  local var="$1" msg="$2" def="${3:-}" nonint="${4:-no}"
  if [[ -n "${!var:-}" ]]; then
    return 0
  fi
  if is_yes "${nonint}"; then
    [[ -n "${def}" ]] || die "missing required parameter: ${var}"
    printf -v "${var}" "%s" "${def}"
    return 0
  fi
  local v=""
  if [[ -n "${def}" ]]; then
    read -r -p "${msg} [${def}]: " v
    v="${v:-$def}"
  else
    read -r -p "${msg}: " v
  fi
  [[ -n "${v}" ]] || die "missing value for ${var}"
  printf -v "${var}" "%s" "${v}"
}

detect_pkg_mgr() {
  if command -v dnf >/dev/null 2>&1; then echo dnf; return; fi
  if command -v apt-get >/dev/null 2>&1; then echo apt; return; fi
  die "unsupported OS: need dnf or apt-get"
}

ensure_git() {
  command -v git >/dev/null 2>&1 && return 0
  local pkg_mgr
  pkg_mgr="$(detect_pkg_mgr)"
  case "${pkg_mgr}" in
    dnf) dnf -y install git ;;
    apt)
      export DEBIAN_FRONTEND=noninteractive
      apt-get update -y
      apt-get install -y git
      ;;
  esac
  command -v git >/dev/null 2>&1 || die "failed to install git"
}

default_origin_branch() {
  # Prints default origin branch name (e.g. "main"), or empty.
  # Must be run inside a git repo.
  local sym
  sym="$(git symbolic-ref --quiet --short refs/remotes/origin/HEAD 2>/dev/null || true)"
  sym="${sym#origin/}"
  if [[ -n "${sym}" ]]; then
    printf "%s" "${sym}"
  fi
}

checkout_ref_best_effort() {
  # Must be run inside a git repo.
  local ref="$1"
  [[ -n "${ref}" ]] || return 0

  # If ref looks like a remote branch, normalize to local branch name.
  if [[ "${ref}" == origin/* ]]; then
    ref="${ref#origin/}"
  fi

  # Prefer local branch if it exists; otherwise try to create tracking branch from origin/<ref>.
  if git show-ref --verify --quiet "refs/heads/${ref}"; then
    git checkout --force "${ref}"
    return 0
  fi
  if git show-ref --verify --quiet "refs/remotes/origin/${ref}"; then
    git checkout --force -B "${ref}" --track "origin/${ref}"
    return 0
  fi

  # Fallback: allow detached checkout for tags/commits.
  git checkout --force "${ref}"
}

clone_or_update_repo() {
  local url="$1" dir="$2" update="$3" ref="$4" depth="$5"
  [[ -n "${url}" ]] || die "repo url is empty"
  [[ -n "${dir}" ]] || die "install dir is empty"
  ensure_git
  mkdir -p "$(dirname "${dir}")"

  if [[ -d "${dir}/.git" ]]; then
    (cd "${dir}" && git fetch --all --tags)

    if is_yes "${update}" && [[ -z "${ref}" ]]; then
      # Keep servers deterministic: default to origin's default branch.
      local def
      def="$(cd "${dir}" && default_origin_branch)"
      if [[ -n "${def}" ]]; then
        ref="${def}"
      fi
    fi

    if is_yes "${update}"; then
      say "Updating existing repo in ${dir}..."
      (cd "${dir}" && checkout_ref_best_effort "${ref}" && git pull --ff-only)
    else
      say "Using existing repo in ${dir} (update=no)."
    fi
    if [[ -n "${ref}" ]]; then
      say "Checked out ref: ${ref}"
    fi
    return 0
  fi
  if [[ -e "${dir}" && ! -d "${dir}" ]]; then
    die "install-dir exists and is not a directory: ${dir}"
  fi
  if [[ -d "${dir}" && -n "$(ls -A "${dir}" 2>/dev/null || true)" ]]; then
    die "install-dir is not empty and not a git repo: ${dir} (use a clean dir)"
  fi
  say "Cloning repo: ${url} -> ${dir}"
  if [[ -n "${depth}" ]]; then
    git clone --depth "${depth}" "${url}" "${dir}"
  else
    git clone "${url}" "${dir}"
  fi
  if [[ -n "${ref}" ]]; then
    say "Checking out ref: ${ref}"
    (cd "${dir}" && git fetch --all --tags && checkout_ref_best_effort "${ref}")
  fi
}

install_packages_dnf() {
  say "Installing packages via dnf..."
  dnf -y install ca-certificates curl tar gzip git jq systemd
  dnf -y install python3 python3-pip || true

  # eBPF/BCC toolchain
  dnf -y install clang llvm bpftool kernel-headers "kernel-devel-$(uname -r)" || true
  dnf -y install bcc bcc-tools python3-bcc || true

  # network tools
  dnf -y install tcpdump || true

  # certbot
  dnf -y install certbot || true

  # p0f often lives in EPEL
  if ! rpm -q p0f >/dev/null 2>&1; then
    dnf -y install epel-release || true
    dnf -y install p0f || true
  fi
}

install_packages_apt() {
  say "Installing packages via apt..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y ca-certificates curl tar gzip git jq systemd
  apt-get install -y python3 python3-pip || true

  # eBPF/BCC toolchain
  apt-get install -y clang llvm bpftool linux-headers-$(uname -r) || true
  apt-get install -y bpfcc-tools python3-bcc || true

  apt-get install -y tcpdump || true
  apt-get install -y certbot || true
  apt-get install -y p0f || true
}

ensure_go() {
  local want="$1" mode="$2" # mode: auto|yes|no
  local have=""
  if command -v go >/dev/null 2>&1; then
    have="$(go env GOVERSION 2>/dev/null || true)"
  fi
  if [[ "${mode}" == "no" ]]; then
    say "Go install disabled (install-go=no)."
    command -v go >/dev/null 2>&1 || die "go not found; install it or pass --install-go yes"
    return 0
  fi

  if [[ -n "${have}" ]]; then
    # have like "go1.25.0"
    local hv="${have#go}"
    if [[ "${hv}" == "${want}"* ]]; then
      say "Go already installed: ${have}"
      return 0
    fi
    if [[ "${mode}" == "auto" ]]; then
      # Accept newer major/minor if it satisfies go.mod; we only enforce if hv < want is obvious.
      # Simple heuristic: if version string starts with "1." compare minor.
      :
    fi
  fi

  say "Installing Go ${want} from go.dev..."
  local arch os url tmp
  os="linux"
  arch="$(uname -m)"
  case "${arch}" in
    x86_64|amd64) arch="amd64" ;;
    aarch64|arm64) arch="arm64" ;;
    *) die "unsupported arch for Go install: $(uname -m)" ;;
  esac
  url="https://go.dev/dl/go${want}.${os}-${arch}.tar.gz"
  tmp="$(mktemp -d)"
  curl -fsSL "${url}" -o "${tmp}/go.tgz" || die "failed to download ${url}"
  rm -rf /usr/local/go
  tar -C /usr/local -xzf "${tmp}/go.tgz"
  rm -rf "${tmp}"

  # Ensure /usr/local/go/bin is in PATH for systemd shells and interactive users
  if ! grep -q "/usr/local/go/bin" /etc/profile.d/go-path.sh 2>/dev/null; then
    cat > /etc/profile.d/go-path.sh <<'EOF'
export PATH="/usr/local/go/bin:${PATH}"
EOF
    chmod 0644 /etc/profile.d/go-path.sh
  fi
  export PATH="/usr/local/go/bin:${PATH}"
  command -v go >/dev/null 2>&1 || die "go install failed"
  say "Go installed: $(go version)"
}

write_env_files() {
  local envdir="/etc/fp"
  mkdir -p "${envdir}"
  chmod 700 "${envdir}"
  umask 077

  local ws_pub=""
  if [[ -n "${DOMAIN}" ]]; then
    ws_pub="wss://${DOMAIN}:8443/ws"
  fi

  cat > "${envdir}/fp-upstream.env" <<EOF
# Managed by deploy/install.sh
FP_LISTEN=${UPSTREAM_LISTEN}
FP_PUBLIC_HOST=${DOMAIN}
FP_README_PATH=${REPO_DIR}/README.md
FP_ACCESS_LOG=0
FP_WS_PUBLIC_URL=${ws_pub}
FP_WS_FANOUT=2
FP_WS_PAYLOAD_BYTES=4096
FP_WS_INTERVAL_MS=80
FP_WS_MAX_MS=13000
FP_PCAP_IFACE=${PCAP_IFACE}
FP_PCAP_TCPDUMP=${PCAP_TCPDUMP}
FP_PCAP_SAVE_DIR=${PCAP_SAVE_DIR}
FP_PCAP_EXTRA_PORTS=
FP_H2EDGE_JOURNAL_UNIT=fp-h2edge
TTL_API=${TTL_API}
FP_TRUSTED_PROXY_CIDRS=${TRUSTED_PROXY_CIDRS}
EOF

  cat > "${envdir}/fp-h2edge.env" <<EOF
# Managed by deploy/install.sh
H2EDGE_LISTEN=${H2EDGE_LISTEN}
H2EDGE_HTTP_LISTEN=${H2EDGE_HTTP_LISTEN}
H2EDGE_UPSTREAM=http://${UPSTREAM_LISTEN}
H2EDGE_CERT=${H2EDGE_CERT}
H2EDGE_KEY=${H2EDGE_KEY}
H2EDGE_WS_LISTEN=0.0.0.0:8443
H2EDGE_WS_RELAY_SECONDS=12
H2EDGE_WS_SERVER_INTERVAL_MS=800
H2EDGE_WS_SERVER_MSG_BYTES=80
H2EDGE_H2_CAPTURE_MS=800
H2EDGE_H2_MAX_FRAMES=256
H2EDGE_H2_STOP_AFTER_HEADERS=0
H2EDGE_ACCESS_LOG=0
H2EDGE_WS_ACCESS_LOG=0
EOF
}

install_systemd_units() {
  say "Installing systemd units..."

  cat > /etc/systemd/system/fp-upstream.service <<'EOF'
[Unit]
Description=Fingerprint upstream (UI/API)
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/fp/fp-upstream.env
ExecStart=/usr/local/bin/fp-upstream
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/fp-h2edge.service <<'EOF'
[Unit]
Description=Fingerprint HTTP/2 edge (TLS+H2 terminator)
After=network.target

[Service]
Type=simple
EnvironmentFile=/etc/fp/fp-h2edge.env
ExecStart=/usr/local/bin/fp-h2edge
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/fp-netagent.service <<'EOF'
[Unit]
Description=Fingerprint netagent (TTL via eBPF/BCC)
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/fp-netagent
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

  cat > /etc/systemd/system/p0f.service <<'EOF'
[Unit]
Description=p0f passive TCP/IP stack fingerprinting
After=network.target

[Service]
Type=simple
ExecStart=/usr/sbin/p0f -i any -s /var/run/p0f.sock -o /var/log/p0f.log
Restart=on-failure
RestartSec=1

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now p0f fp-netagent fp-upstream fp-h2edge
}

build_and_install() {
  local repo="$1"
  say "Building and installing binaries from ${repo}..."
  export PATH="/usr/local/go/bin:${PATH}"

  (cd "${repo}/fp/h2edge" && go mod download && go build -o fp-h2edge .)
  install -m 0755 "${repo}/fp/h2edge/fp-h2edge" /usr/local/bin/fp-h2edge

  (cd "${repo}/fp/upstream" && go mod download && go build -o fp-upstream .)
  install -m 0755 "${repo}/fp/upstream/fp-upstream" /usr/local/bin/fp-upstream

  install -m 0755 "${repo}/fp/netagent/fp_netagent.py" /usr/local/bin/fp-netagent
}

issue_cert_if_needed() {
  if ! is_yes "${ISSUE_CERT}"; then
    say "Skipping certificate issuance (issue-cert=no)."
    return 0
  fi
  [[ -n "${DOMAIN}" ]] || die "--domain is required when issuing cert"
  [[ -n "${EMAIL}" ]] || die "--email is required when issuing cert"
  say "Issuing/renewing Let's Encrypt certificate for ${DOMAIN}..."

  # Free :80 (certbot standalone)
  systemctl stop fp-h2edge >/dev/null 2>&1 || true

  certbot certonly --standalone --non-interactive --agree-tos --email "${EMAIL}" -d "${DOMAIN}"

  H2EDGE_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
  H2EDGE_KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
  [[ -f "${H2EDGE_CERT}" ]] || die "cert not found at ${H2EDGE_CERT}"
  [[ -f "${H2EDGE_KEY}" ]] || die "key not found at ${H2EDGE_KEY}"
}

main() {
  DOMAIN=""
  EMAIL=""
  REPO_DIR=""
  REPO_URL="https://github.com/SysAdminKo/fingerprint-stack.git"
  INSTALL_DIR="/opt/fingerprint-stack"
  UPDATE_REPO="no"
  REF=""
  DEPTH=""
  GO_VERSION="1.25.0"
  INSTALL_GO="auto"
  ISSUE_CERT="auto"
  NON_INTERACTIVE="no"
  DRY_RUN="no"

  H2EDGE_LISTEN="0.0.0.0:443"
  H2EDGE_HTTP_LISTEN="0.0.0.0:80"
  UPSTREAM_LISTEN="127.0.0.1:9000"
  TTL_API="http://127.0.0.1:9100"
  TRUSTED_PROXY_CIDRS="127.0.0.1/8,::1/128"
  PCAP_IFACE="any"
  PCAP_TCPDUMP="/usr/sbin/tcpdump"
  PCAP_SAVE_DIR="/var/lib/fp/pcap"

  # If we skip cert issuance, we still need cert/key paths to start fp-h2edge.
  # Default placeholders; user can overwrite later.
  H2EDGE_CERT="/etc/letsencrypt/live/CHANGE_ME/fullchain.pem"
  H2EDGE_KEY="/etc/letsencrypt/live/CHANGE_ME/privkey.pem"

  while [[ $# -gt 0 ]]; do
    case "$1" in
      --domain) DOMAIN="${2:-}"; shift 2 ;;
      --email) EMAIL="${2:-}"; shift 2 ;;
      --repo-dir) REPO_DIR="${2:-}"; shift 2 ;;
      --repo-url) REPO_URL="${2:-}"; shift 2 ;;
      --install-dir) INSTALL_DIR="${2:-}"; shift 2 ;;
      --update) UPDATE_REPO="${2:-}"; shift 2 ;;
      --ref) REF="${2:-}"; shift 2 ;;
      --depth) DEPTH="${2:-}"; shift 2 ;;
      --go-version) GO_VERSION="${2:-}"; shift 2 ;;
      --install-go) INSTALL_GO="${2:-}"; shift 2 ;;
      --issue-cert) ISSUE_CERT="${2:-}"; shift 2 ;;
      --h2edge-listen) H2EDGE_LISTEN="${2:-}"; shift 2 ;;
      --h2edge-http-listen) H2EDGE_HTTP_LISTEN="${2:-}"; shift 2 ;;
      --upstream-listen) UPSTREAM_LISTEN="${2:-}"; shift 2 ;;
      --ttl-api) TTL_API="${2:-}"; shift 2 ;;
      --trusted-proxy-cidrs) TRUSTED_PROXY_CIDRS="${2:-}"; shift 2 ;;
      --pcap-iface) PCAP_IFACE="${2:-}"; shift 2 ;;
      --pcap-tcpdump) PCAP_TCPDUMP="${2:-}"; shift 2 ;;
      --pcap-save-dir) PCAP_SAVE_DIR="${2:-}"; shift 2 ;;
      --dry-run) DRY_RUN="yes"; shift ;;
      --non-interactive) NON_INTERACTIVE="yes"; shift ;;
      -h|--help) usage; exit 0 ;;
      *) die "unknown arg: $1" ;;
    esac
  done

  # Interactive prompts (only for domain/email, the rest has reasonable defaults).
  if [[ "${ISSUE_CERT}" == "auto" ]]; then
    if [[ -n "${DOMAIN}" ]]; then
      ISSUE_CERT="yes"
    else
      ISSUE_CERT="no"
    fi
  fi

  if is_yes "${ISSUE_CERT}"; then
    prompt DOMAIN "Domain to serve (DNS A/AAAA must point here)" "${DOMAIN:-}" "${NON_INTERACTIVE}"
    prompt EMAIL "Let's Encrypt email" "${EMAIL:-}" "${NON_INTERACTIVE}"
  else
    if [[ -z "${DOMAIN}" ]] && ! is_yes "${NON_INTERACTIVE}"; then
      read -r -p "Public domain (optional, for UI only; empty to skip): " DOMAIN || true
    fi
  fi

  if [[ -z "${REPO_DIR}" ]]; then
    if [[ -n "${REPO_URL}" ]]; then
      REPO_DIR="${INSTALL_DIR}"
      # In dry-run we don't clone; keep REPO_DIR at install-dir for the plan.
      if ! is_yes "${DRY_RUN}"; then
        clone_or_update_repo "${REPO_URL}" "${REPO_DIR}" "${UPDATE_REPO}" "${REF}" "${DEPTH}"
      fi
    else
      # auto-detect repo root based on script location
      REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    fi
  fi

  if is_yes "${DRY_RUN}"; then
    # We intentionally do not require root and do not touch disk/network beyond tiny checks.
    print_dry_run_plan
    exit 0
  fi

  need_root "$@"
  [[ -d "${REPO_DIR}/fp/h2edge" ]] || die "repo-dir does not look like fingerprint-stack: ${REPO_DIR}"

  local pkg_mgr
  pkg_mgr="$(detect_pkg_mgr)"
  case "${pkg_mgr}" in
    dnf) install_packages_dnf ;;
    apt) install_packages_apt ;;
  esac

  ensure_go "${GO_VERSION}" "${INSTALL_GO}"

  build_and_install "${REPO_DIR}"

  issue_cert_if_needed

  if [[ -n "${DOMAIN}" && -f "/etc/letsencrypt/live/${DOMAIN}/fullchain.pem" ]]; then
    H2EDGE_CERT="/etc/letsencrypt/live/${DOMAIN}/fullchain.pem"
    H2EDGE_KEY="/etc/letsencrypt/live/${DOMAIN}/privkey.pem"
  fi

  write_env_files
  install_systemd_units

  say "Installation complete."
  say "Upstream: https://${DOMAIN:-<domain-not-set>}/ (via fp-h2edge)"
  say "Services: systemctl status fp-h2edge fp-upstream fp-netagent p0f"
}

main "$@"

