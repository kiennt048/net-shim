#!/bin/sh
set -e

APP_NAME="net-shim"

GITHUB_USER="kiennt048"
REPO="net-shim"
BRANCH="main"

BIN_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${REPO}/${BRANCH}/net-shim"
RC_URL="https://raw.githubusercontent.com/${GITHUB_USER}/${REPO}/${BRANCH}/net-shim.rc"

BIN_PATH="/usr/local/sbin/${APP_NAME}"
RC_PATH="/usr/local/etc/rc.d/${APP_NAME}"
RC_CONF="/etc/rc.conf.local"

echo "[+] Installing ${APP_NAME}"

fetch -o "${BIN_PATH}" "${BIN_URL}"
fetch -o "${RC_PATH}" "${RC_URL}"

chmod +x "${BIN_PATH}"
chmod +x "${RC_PATH}"

grep -q '^net_shim_enable="YES"' "${RC_CONF}" 2>/dev/null || \
  echo 'net_shim_enable="YES"' >> "${RC_CONF}"

service "${APP_NAME}" restart || service "${APP_NAME}" start

echo "[✓] ${APP_NAME} installed"
