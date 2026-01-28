#!/bin/sh
set -eu

### ===== CONFIG =====
APP="netshim"
REPO_BASE="https://raw.githubusercontent.com/kiennt048/net-shim/main"
BIN_URL="${REPO_BASE}/net-shim"
BIN_DST="/usr/local/sbin/net-shim"
RC_FILE="/usr/local/etc/rc.d/netshim"
LOG="/var/log/netshim.log"
HEALTH_URL="http://127.0.0.1:8080/health"
RESTAPI_PKG_URL="https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download/pfSense-2.8.1-pkg-RESTAPI.pkg"

# 🔐 UPDATE THIS AFTER EACH BUILD
EXPECTED_SHA256="6a6e19c3904ba1ae577311447c5876ff4b2d305d01415197fb0434d03ae8b82a"
### ==================

TMPDIR="/tmp/netshim.$$"
BIN_TMP="${TMPDIR}/net-shim"
BIN_NEW="${TMPDIR}/net-shim.new"
BACKUP=""
FIRST_FLAG="/var/db/netshim.first_install"

cleanup() { rm -rf "${TMPDIR}"; }

rollback() {
    echo "==> Rolling back"
    service netshim stop 2>/dev/null || true
    if [ -n "${BACKUP}" ] && [ -f "${BACKUP}" ]; then
        mv -f "${BACKUP}" "${BIN_DST}"
        service netshim start 2>/dev/null || true
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
install_pkg "Zabbix Agent7" "zabbix7-agent"         "zabbix7-agent"
install_pkg "WireGuard"     "pfSense-pkg-WireGuard" "pfSense-pkg-WireGuard"

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
if service netshim onestatus >/dev/null 2>&1; then
    echo "==> Stopping running service"
    service netshim stop 2>/dev/null || true
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

# Create RC service script
if [ ! -f "${RC_FILE}" ]; then
    echo "==> Creating service"
    cat << 'EOF' > "${RC_FILE}"
#!/bin/sh
# PROVIDE: netshim
# REQUIRE: LOGIN NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="netshim"
rcvar="netshim_enable"
command="/usr/local/sbin/net-shim"
pidfile="/var/run/netshim.pid"

start_cmd="netshim_start"
stop_cmd="netshim_stop"
status_cmd="netshim_status"

netshim_start() {
    echo "Starting ${name}..."
    /usr/sbin/daemon -p ${pidfile} -o /var/log/netshim.log ${command}
}

netshim_stop() {
    if [ -f ${pidfile} ]; then
        echo "Stopping ${name}..."
        kill $(cat ${pidfile}) 2>/dev/null
        rm -f ${pidfile}
    fi
}

netshim_status() {
    if [ -f ${pidfile} ] && kill -0 $(cat ${pidfile}) 2>/dev/null; then
        echo "${name} is running as pid $(cat ${pidfile})"
    else
        echo "${name} is not running"
        return 1
    fi
}

load_rc_config $name
: ${netshim_enable:="NO"}
run_rc_command "$1"
EOF
    chmod +x "${RC_FILE}"
fi

# Enable service
sysrc netshim_enable=YES >/dev/null

# Start service
echo "==> Starting service"
service netshim start || rollback

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
    touch "${FIRST_FLAG}"
    echo "==> First installation detected"
    echo "==> Restoring default configuration..."
    service netshim stop 2>/dev/null || true
    pkill -f /usr/local/sbin/net-shim || true
    sleep 2

    if ${BIN_DST} --init >> "${LOG}" 2>&1; then
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
        for i in 10 9 8 7 6 5 4 3 2 1; do
            printf "\r  Rebooting in %2d seconds... (Press Ctrl+C to cancel)" "$i"
            sleep 1
        done
        echo ""
        echo "==> Rebooting now..."
        # Kill daemon, disable trap, force reboot
        pkill -f /usr/local/sbin/net-shim || true
        trap - EXIT
        rm -rf "${TMPDIR}"
        /sbin/reboot
        sleep 120
    else
        echo "WARNING: Default config restore failed. Check ${LOG}"
        echo "==> Continuing with existing configuration..."
        service netshim start 2>/dev/null || true
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
