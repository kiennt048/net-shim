#!/bin/sh
set -eu

### ===== CONFIG =====
APP="netshim"
REPO_BASE="https://raw.githubusercontent.com/kiennt048/net-shim/main"
BIN_URL="${REPO_BASE}/net-shim"
BIN_DST="/usr/local/sbin/net-shim"
RC_FILE="/usr/local/etc/rc.d/netshim"
RC_LOCAL="/etc/rc.local"
SHELLCMD_SCRIPT="/usr/local/etc/rc.d/netshim_shellcmd.sh"
LOG="/var/log/netshim.log"
PIDFILE="/var/run/netshim.pid"
HEALTH_URL="http://127.0.0.1:8080/health"
RESTAPI_PKG_URL="https://github.com/pfrest/pfSense-pkg-RESTAPI/releases/latest/download/pfSense-2.8.1-pkg-RESTAPI.pkg"
STARTUP_TAG="### NETSHIM_AUTOSTART ###"

# 🔐 UPDATE THIS AFTER EACH BUILD
EXPECTED_SHA256="afd85a3d38d8070c6588e83412543d97ea58bb215bf3e819ce230a8a9882ecaf"
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
    pkill -f /usr/local/sbin/net-shim 2>/dev/null || true
    if [ -n "${BACKUP}" ] && [ -f "${BACKUP}" ]; then
        mv -f "${BACKUP}" "${BIN_DST}"
        /usr/sbin/daemon -f -P ${PIDFILE} -o ${LOG} -t netshim ${BIN_DST} 2>/dev/null || true
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
    service netshim stop 2>/dev/null || true
    pkill -f /usr/local/sbin/net-shim 2>/dev/null || true
    sleep 1
    rm -f "${BIN_DST}" "${RC_FILE}" "${FIRST_FLAG}" "${PIDFILE}"
    rm -f "${SHELLCMD_SCRIPT}" 2>/dev/null
    rm -f "${BIN_DST}".bak.* 2>/dev/null
    sysrc -x netshim_enable 2>/dev/null || true
    # Remove rc.local hook
    if [ -f "${RC_LOCAL}" ]; then
        sed -i '' "/${STARTUP_TAG}/d" "${RC_LOCAL}" 2>/dev/null || true
    fi
    # Remove config.xml shellcmd entry
    CONFIG_XML="/cf/conf/config.xml"
    if [ -f "${CONFIG_XML}" ]; then
        sed -i '' "\|<shellcmd>${SHELLCMD_SCRIPT}</shellcmd>|d" "${CONFIG_XML}" 2>/dev/null || true
    fi
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

# ===================================================================
# AUTOSTART HOOKS (multiple methods for pfSense 2.8.1 reliability)
# ===================================================================

# --- Method 1: Standard rc.d script ---
echo "==> [Autostart] Installing rc.d service script"
cat << 'RCEOF' > "${RC_FILE}"
#!/bin/sh
# PROVIDE: netshim
# REQUIRE: LOGIN NETWORKING
# KEYWORD: shutdown

. /etc/rc.subr

name="netshim"
rcvar="netshim_enable"
command="/usr/local/sbin/net-shim"
pidfile="/var/run/${name}.pid"
command_args=""

start_cmd="netshim_start"
stop_cmd="netshim_stop"
status_cmd="netshim_status"

netshim_start() {
    if [ -f ${pidfile} ] && kill -0 "$(cat ${pidfile})" 2>/dev/null; then
        echo "${name} already running as pid $(cat ${pidfile})"
        return 0
    fi
    echo "Starting ${name}..."
    /usr/sbin/daemon -f -P ${pidfile} -o /var/log/netshim.log -t ${name} ${command}
}

netshim_stop() {
    if [ -f ${pidfile} ]; then
        echo "Stopping ${name}..."
        kill "$(cat ${pidfile})" 2>/dev/null
        rm -f ${pidfile}
    else
        pkill -f ${command} 2>/dev/null
    fi
}

netshim_status() {
    if [ -f ${pidfile} ] && kill -0 "$(cat ${pidfile})" 2>/dev/null; then
        echo "${name} is running as pid $(cat ${pidfile})"
    else
        echo "${name} is not running"
        return 1
    fi
}

load_rc_config $name
: ${netshim_enable:="NO"}
run_rc_command "$1"
RCEOF
chmod +x "${RC_FILE}"
sysrc netshim_enable=YES >/dev/null

# --- Method 2: /etc/rc.local (primary autostart for pfSense) ---
echo "==> [Autostart] Installing /etc/rc.local hook"
touch "${RC_LOCAL}"
chmod +x "${RC_LOCAL}"
# Add shebang if missing
head -1 "${RC_LOCAL}" | grep -q '^#!/bin/sh' || sed -i '' '1i\
#!/bin/sh
' "${RC_LOCAL}" 2>/dev/null || true
# Remove old entry if exists, then add fresh
sed -i '' "/${STARTUP_TAG}/d" "${RC_LOCAL}" 2>/dev/null || true
cat >> "${RC_LOCAL}" << RCLOCAL
/usr/sbin/daemon -f -P ${PIDFILE} -o ${LOG} -t netshim ${BIN_DST} ${STARTUP_TAG}
RCLOCAL
echo "==> [Autostart] rc.local hook added"

# --- Method 3: Standalone shellcmd script (pfSense earlyshellcmd compatible) ---
echo "==> [Autostart] Installing shellcmd script"
cat << SHEOF > "${SHELLCMD_SCRIPT}"
#!/bin/sh
# netshim autostart - standalone launcher
# Can be called from pfSense shellcmd / earlyshellcmd
BIN="${BIN_DST}"
PID="${PIDFILE}"
LOGF="${LOG}"

if [ -f "\${PID}" ] && kill -0 "\$(cat "\${PID}")" 2>/dev/null; then
    exit 0
fi
/usr/sbin/daemon -f -P "\${PID}" -o "\${LOGF}" -t netshim "\${BIN}"
SHEOF
chmod +x "${SHELLCMD_SCRIPT}"

# --- Method 4: pfSense config.xml shellcmd (survives firmware upgrades) ---
echo "==> [Autostart] Adding pfSense shellcmd to config.xml"
SHELLCMD_LINE="${SHELLCMD_SCRIPT}"
CONFIG_XML="/cf/conf/config.xml"
if [ -f "${CONFIG_XML}" ]; then
    if ! grep -q "${SHELLCMD_SCRIPT}" "${CONFIG_XML}" 2>/dev/null; then
        # Insert shellcmd entry before </system> tag
        sed -i '' "/<\/system>/i\\
		<shellcmd>${SHELLCMD_LINE}</shellcmd>
" "${CONFIG_XML}" 2>/dev/null && echo "==> [Autostart] shellcmd added to config.xml" || echo "==> [Autostart] WARNING: could not add shellcmd to config.xml"
    else
        echo "==> [Autostart] shellcmd already in config.xml"
    fi
else
    echo "==> [Autostart] WARNING: config.xml not found, skipping"
fi

echo "==> [Autostart] 4 methods installed: rc.d + rc.local + shellcmd script + config.xml"

# Start service now (try rc.d first, fallback to direct daemon)
echo "==> Starting service"
if ! service netshim start 2>/dev/null; then
    echo "==> rc.d start failed, using direct daemon launch"
    /usr/sbin/daemon -f -P ${PIDFILE} -o ${LOG} -t netshim ${BIN_DST} || rollback
fi

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
    service netshim stop 2>/dev/null || true
    pkill -f /usr/local/sbin/net-shim 2>/dev/null || true
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
        /usr/sbin/daemon -f -P ${PIDFILE} -o ${LOG} -t netshim ${BIN_DST} 2>/dev/null || true
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
