#!/bin/sh
set -e

APP="netshim"
BIN_DST="/usr/local/sbin/net-shim"
RC_FILE="/usr/local/etc/rc.d/netshim"
LOG="/var/log/netshim.log"
TMPDIR="$(mktemp -d)"
BIN_TMP="${TMPDIR}/net-shim"

BIN_URL="https://raw.githubusercontent.com/kiennt048/net-shim/main/net-shim"

cleanup() {
    rm -rf "${TMPDIR}"
}
trap cleanup EXIT

echo "==> Installing ${APP}..."

# --- must be root ---
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: must run as root"
    exit 1
fi

# --- fetch binary ---
echo "==> Downloading binary..."
fetch -o "${BIN_TMP}" "${BIN_URL}"

chmod +x "${BIN_TMP}"

# --- stop service if running ---
if service netshim onestatus >/dev/null 2>&1; then
    echo "==> Stopping running service..."
    service netshim stop || true
fi

# --- backup old binary ---
if [ -f "${BIN_DST}" ]; then
    echo "==> Backing up existing binary..."
    cp -f "${BIN_DST}" "${BIN_DST}.bak.$(date +%s)"
fi

# --- install binary ---
echo "==> Installing binary..."
install -m 755 "${BIN_TMP}" "${BIN_DST}"

# --- create service if missing ---
if [ ! -f "${RC_FILE}" ]; then
    echo "==> Creating service..."
    cat << 'EOF' > "${RC_FILE}"
#!/bin/sh
# PROVIDE: netshim
# REQUIRE: LOGIN
# KEYWORD: shutdown

. /etc/rc.subr

name="netshim"
rcvar="netshim_enable"
command="/usr/local/sbin/net-shim"
pidfile="/var/run/netshim.pid"

start_cmd="netshim_start"

netshim_start() {
    daemon -p ${pidfile} ${command} >> /var/log/netshim.log 2>&1
}

load_rc_config $name
: ${netshim_enable:="NO"}
run_rc_command "$1"
EOF
    chmod +x "${RC_FILE}"
fi

# --- enable + start ---
sysrc netshim_enable=YES >/dev/null
service netshim start

# --- verify ---
sleep 1
if sockstat -4 -l | grep -q ':8080'; then
    echo "==> net-shim RUNNING (8080)"
else
    echo "WARNING: net-shim did not start"
    echo "Check log: ${LOG}"
fi

echo "==> Install DONE"
