#!/bin/sh
set -eu

### ===== CONFIG =====
APP="netshim"
REPO_BASE="https://raw.githubusercontent.com/kiennt048/net-shim/main"
BIN_URL="${REPO_BASE}/net-shim"
BIN_DST="/usr/local/sbin/net-shim"
RC_FILE="/usr/local/etc/rc.d/netshim"
LOCK_FILE="/var/run/netshim.pid"
LOG_FILE="/var/log/netshim.log"
START_CMD="/usr/sbin/daemon -f -r -R 5 -P ${LOCK_FILE} -o ${LOG_FILE} -t netshim ${BIN_DST}"
LOG="/var/log/netshim.log"
HEALTH_URL="http://127.0.0.1:8080/health"
RESTAPI_PKG_URL="https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download/pfSense-2.8.1-pkg-RESTAPI.pkg"

# 🔐 UPDATE THIS AFTER EACH BUILD
EXPECTED_SHA256="0d193865d9cad418dfe5e9fcf76f344e7105492909b7384fe5d4975fe4592a50"
### ==================

TMPDIR="/tmp/netshim.$$"
BIN_TMP="${TMPDIR}/net-shim"
BIN_NEW="${TMPDIR}/net-shim.new"
BACKUP=""
FIRST_FLAG="/var/db/netshim.first_install"

cleanup() { rm -rf "${TMPDIR}"; }

rollback() {
    echo "==> Rolling back"
    pkill -f "${BIN_DST}" 2>/dev/null || true
    if [ -n "${BACKUP}" ] && [ -f "${BACKUP}" ]; then
        mv -f "${BACKUP}" "${BIN_DST}"
        eval "${START_CMD}" || true
        echo "==> Rollback completed"
    else
        echo "==> No backup to rollback"
    fi
    cleanup
    exit 1
}

trap cleanup EXIT

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║     BEYONDNET Firewall Control Installer   ║"
echo "╚════════════════════════════════════════════╝"
echo ""

# Check root
[ "$(id -u)" = "0" ] || { echo "ERROR: must run as root"; exit 1; }

# Check pfSense
[ -f "/etc/inc/config.inc" ] || [ -f "/cf/conf/config.xml" ] || {
    echo "WARNING: This doesn't appear to be a pfSense system"
    echo "Continue anyway? [y/N]"
    read -r answer
    [ "$answer" = "y" ] || [ "$answer" = "Y" ] || exit 1
}

# Detect existing installation and clean up for fresh install
if [ -f "${BIN_DST}" ] || [ -f "${FIRST_FLAG}" ] || [ -f "${RC_FILE}" ]; then
    echo "==> Existing installation detected, removing..."
    pkill -f "${BIN_DST}" 2>/dev/null || true
    sleep 1
    rm -f "${BIN_DST}" "${RC_FILE}" "${FIRST_FLAG}" /var/run/netshim.pid
    rm -f "${BIN_DST}".bak.* 2>/dev/null
    sysrc -x netshim_enable 2>/dev/null || true
    echo "==> Old installation removed"
fi

# Install required packages if missing
install_pkg() {
    _name="$1"
    _check="$2"
    _source="$3"

    if ! pkg info "${_check}" >/dev/null 2>&1; then
        echo "==> ${_name} not found, installing..."
        if echo "${_source}" | grep -q "^http"; then
            pkg-static add "${_source}" && echo "==> ${_name} installed" || echo "WARNING: ${_name} install failed"
        else
            pkg install -y "${_source}" && echo "==> ${_name} installed" || echo "WARNING: ${_name} install failed"
        fi
    else
        echo "==> ${_name} already installed"
    fi
}

install_pkg "REST API"      "pfSense-pkg-RESTAPI"  "${RESTAPI_PKG_URL}"
install_pkg "Zabbix Agent 7" "zabbix7-agent"        "zabbix7-agent"
install_pkg "WireGuard"      "pfSense-pkg-WireGuard" "pfSense-pkg-WireGuard"

mkdir -p "${TMPDIR}"

# Download binary
echo "==> Downloading binary"
fetch -R -o "${BIN_TMP}" "${BIN_URL}" || {
    echo "ERROR: Failed to download binary"
    exit 1
}
chmod +x "${BIN_TMP}"

# Verify checksum
echo "==> Verifying checksum"
DOWNLOADED_SHA256="$(sha256 -q "${BIN_TMP}")"
if [ "${EXPECTED_SHA256}" = "PUT_REAL_SHA256_HERE" ]; then
    echo "WARNING: SHA256 not configured, skipping verification"
    echo "Downloaded SHA256: ${DOWNLOADED_SHA256}"
elif [ "${DOWNLOADED_SHA256}" != "${EXPECTED_SHA256}" ]; then
    echo "ERROR: Checksum mismatch"
    echo "Expected: ${EXPECTED_SHA256}"
    echo "Got:      ${DOWNLOADED_SHA256}"
    exit 1
else
    echo "==> Checksum OK"
fi

# Stop existing service
if pgrep -f "${BIN_DST}" >/dev/null 2>&1; then
    echo "==> Stopping running service"
    pkill -f "${BIN_DST}" 2>/dev/null || true
    sleep 2
fi

# Backup existing binary
if [ -f "${BIN_DST}" ]; then
    BACKUP="${BIN_DST}.bak.$(date +%s)"
    echo "==> Backing up existing binary to ${BACKUP}"
    cp -f "${BIN_DST}" "${BACKUP}"
fi

# Install binary (atomic)
echo "==> Installing binary"
cp -f "${BIN_TMP}" "${BIN_NEW}"
chmod 755 "${BIN_NEW}"
mv -f "${BIN_NEW}" "${BIN_DST}"

# Cleanup old RC service if exists
if [ -f "${RC_FILE}" ]; then
    echo "==> Removing old RC service script"
    service netshim stop 2>/dev/null || true
    rm -f "${RC_FILE}"
    sysrc -x netshim_enable 2>/dev/null || true
fi

# Install to /etc/rc.local
echo "==> Configuring /etc/rc.local startup"
LOCK_FILE="/var/run/netshim.pid"
LOG_FILE="/var/log/netshim.log"
START_CMD="/usr/sbin/daemon -f -r -R 5 -P ${LOCK_FILE} -o ${LOG_FILE} -t netshim ${BIN_DST}"

if [ ! -f "/etc/rc.local" ]; then
    touch "/etc/rc.local"
fi

if ! grep -q "${BIN_DST}" "/etc/rc.local"; then
    echo "" >> "/etc/rc.local"
    echo "# netshim startup" >> "/etc/rc.local"
    echo "${START_CMD}" >> "/etc/rc.local"
    echo "==> Added to /etc/rc.local"
else
    # Update the line if it exists but might be old format? 
    # For simplicity, we assume if the binary path is there, it's configured.
    # But better to replace the line to ensure flags are current.
    sed -i '' "\|${BIN_DST}|d" "/etc/rc.local"
    echo "${START_CMD}" >> "/etc/rc.local"
    echo "==> Updated /etc/rc.local"
fi

chmod +x "/etc/rc.local"

# Start service immediately
echo "==> Starting service"
eval "${START_CMD}"

# Health check
echo "==> Waiting for health check"
HEALTH_OK=0
for i in 1 2 3 4 5 6 7 8 9 10; do
    sleep 1
    if fetch -q -o /dev/null "${HEALTH_URL}" 2>/dev/null; then
        HEALTH_OK=1
        break
    fi
    echo "    Attempt ${i}/10..."
done

if [ "${HEALTH_OK}" -ne 1 ]; then
    echo "ERROR: Health check failed"
    rollback
fi

# First install: restore default config and reboot (single reboot)
if [ ! -f "${FIRST_FLAG}" ]; then
    echo "==> First installation detected"
    echo "==> Restoring default configuration..."
    pkill -f "${BIN_DST}" 2>/dev/null || true
    sleep 2

    if ${BIN_DST} --init >> "${LOG}" 2>&1; then
        # Mark first install AFTER successful config restore
        touch "${FIRST_FLAG}"

        echo ""
        echo "╔════════════════════════════════════════════╗"
        echo "║      First Install - Config Restored        ║"
        echo "╠════════════════════════════════════════════╣"
        echo "║  Default config restored successfully.     ║"
        echo "║  System will reboot in 10 seconds to       ║"
        echo "║  apply all changes.                        ║"
        echo "║                                            ║"
        echo "║  After reboot:                             ║"
        echo "║  Access: http://<FIREWALL-IP>:8080         ║"
        echo "║  Logs:   /var/log/netshim.log              ║"
        echo "╚════════════════════════════════════════════╝"
        echo ""
        echo "WARNING: System will reboot in 10 seconds..."
        i=10
        while [ "$i" -gt 0 ]; do
            printf "\r  Rebooting in %2d seconds... (Press Ctrl+C to cancel)" "$i"
            sleep 1
            i=$((i - 1))
        done
        echo ""
        echo "==> Rebooting now..."
        # Disable all traps and error exit before reboot
        set +eu
        trap - EXIT
        pkill -f /usr/local/sbin/net-shim 2>/dev/null
        rm -rf "${TMPDIR}" 2>/dev/null
        # Force immediate reboot - nohup ensures it survives SSH disconnect
        nohup /sbin/reboot > /dev/null 2>&1 &
        sleep 120
        exit 0
    else
        echo "WARNING: Default config restore failed. Check ${LOG}"
        echo "==> Continuing with existing configuration..."
        eval "${START_CMD}" || true
    fi
fi

# Cleanup old backups (keep last 3)
echo "==> Cleaning old backups"
ls -t ${BIN_DST}.bak.* 2>/dev/null | tail -n +4 | xargs rm -f 2>/dev/null || true

echo ""
echo "╔════════════════════════════════════════════╗"
echo "║         Installation Successful!           ║"
echo "╠════════════════════════════════════════════╣"
echo "║  Access: http://<FIREWALL-IP>:8080          ║"
echo "║  Logs:   /var/log/netshim.log              ║"
echo "╚════════════════════════════════════════════╝"
echo ""
