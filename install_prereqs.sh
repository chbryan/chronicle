#!/usr/bin/env bash
set -euo pipefail

# Chronicle prereq installer for Debian/Kicksecure
# - Installs system prerequisites via apt
# - Creates/uses a local venv at ./.venv
# - Installs Chronicle python deps listed in README

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV_DIR="${REPO_DIR}/.venv"

# If run with sudo, install python deps as the invoking user (not root)
TARGET_USER="${SUDO_USER:-$(id -un)}"

log() { printf "\n[+] %s\n" "$*"; }
die() { printf "\n[!] %s\n" "$*" >&2; exit 1; }

need_cmd() { command -v "$1" >/dev/null 2>&1 || die "Missing command: $1"; }

need_cmd apt-get
need_cmd python3

if [[ "$(id -u)" -ne 0 ]]; then
  die "Run this script with sudo:  sudo ./install_prereqs.sh"
fi

log "Updating apt indexes…"
apt-get update -y

log "Installing system packages…"
apt-get install -y \
  ca-certificates curl git \
  python3 python3-venv python3-pip

# Optional but handy for inspecting the SQLite DB (the app uses sqlite via Python)
apt-get install -y sqlite3 || true

log "Creating venv at: ${VENV_DIR}"
if id "$TARGET_USER" >/dev/null 2>&1; then
  sudo -u "$TARGET_USER" -H bash -lc "python3 -m venv '${VENV_DIR}'"
  sudo -u "$TARGET_USER" -H bash -lc "source '${VENV_DIR}/bin/activate' && python -m pip install -U pip setuptools wheel"
  # README deps:
  sudo -u "$TARGET_USER" -H bash -lc "source '${VENV_DIR}/bin/activate' && pip install feedparser requests pyyaml beautifulsoup4"
else
  # Fallback (shouldn’t happen unless TARGET_USER is weird)
  python3 -m venv "${VENV_DIR}"
  # shellcheck disable=SC1090
  source "${VENV_DIR}/bin/activate"
  python -m pip install -U pip setuptools wheel
  pip install feedparser requests pyyaml beautifulsoup4
fi

log "Ensuring standard output dirs exist (safe if already present)…"
mkdir -p "${REPO_DIR}/data" "${REPO_DIR}/logs"
chown -R "$TARGET_USER":"$TARGET_USER" "${REPO_DIR}/data" "${REPO_DIR}/logs" "${VENV_DIR}" || true

log "Done."
echo "Activate the environment:"
echo "  cd '${REPO_DIR}'"
echo "  source '.venv/bin/activate'"
echo
echo "Example run:"
echo "  python chronicle.py --config sources.yaml --keyword \"Russia\" --with-preview --export-json"
