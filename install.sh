#!/bin/sh
set -e

APP="netshim"
BIN_SRC="./net-shim"
BIN_DST="/usr/local/sbin/net-shim"
RC_FILE="/usr/local/etc/rc.d/netshim"
LOG="/var/log/netshim.log"
PID="/var/run/netshim.pid"

echo "==> Installing ${APP}..."

# --- sanity checks ---
if [ "$(id -u)" != "0" ]; then
    echo "ERROR: must run as root"
    exit 1
fi

if [ ! -f "${BIN_SRC}" ]; then
    echo "ERROR: net-shim binary not found"
    exit 1
fi

# --- stop service if running ---
if service netshim onestatus >/dev/null 2>&1; then
    echo "==> Stopping running service..."
    service netshim stop || true
fi

# --- backup existing binary ---
if [ -f "${BIN_DST}" ]; then
    echo "==> Backing up existing binary..."
    cp -f "${BIN_DST}" "${BIN_DST}.bak.$(date +%s)"
fi

# --- install binary (SAFE) ---
if [ "$(realpath "${BIN_SRC}")" != "$(realpath "${BIN_DST}" 2>/dev/null || true)" ]; then
    echo "==> Installing binary..."
    install -m 755 "${BIN_SRC}" "${BIN_DST}"
else
    echo "==> Binary already in place, skipping copy"
fi

# --- create rc.d service if missing ---
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
command_background="yes"

start_cmd="netshim_start"

netshim_start() {
    daemon -p ${pidfile} ${command} >> /var/log/netshim.log 2>&1
}

load_rc_config $name
: ${netshim_enable:="NO"}
run_rc_command "$1"
EOF
    chmod +x "${RC_FILE}"
else
    echo "==> Service already exists, skipping"
fi

# --- enable service ---
sysrc netshim_enable=YES >/dev/null

# --- start service ---
echo "==> Starting service..."
service netshim start

# --- final verification ---
sleep 1
if sockstat -4 -l | grep -q ':8080'; then
    echo "==> net-shim is RUNNING (port 8080)"
else
    echo "WARNING: net-shim did not bind to port 8080"
    echo "Check logs: ${LOG}"
fi

echo "==> Install finished"
