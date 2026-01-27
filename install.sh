#!/bin/sh
set -e

APP_NAME="netshim"
BIN_PATH="/usr/local/sbin/net-shim"
RC_PATH="/usr/local/etc/rc.d/netshim"
LOG_PATH="/var/log/netshim.log"

echo "==> Installing ${APP_NAME}..."

# 1. Copy binary (giả sử binary đã build sẵn trong repo)
echo "==> Installing binary..."
install -m 755 net-shim "${BIN_PATH}"

# 2. Create rc.d service
echo "==> Creating service..."
cat << 'EOF' > "${RC_PATH}"
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
stop_cmd="netshim_stop"

netshim_start() {
    echo "Starting net-shim..."
    nohup ${command} >> /var/log/netshim.log 2>&1 &
    echo $! > ${pidfile}
}

netshim_stop() {
    if [ -f "${pidfile}" ]; then
        kill "$(cat ${pidfile})" && rm -f "${pidfile}"
        echo "net-shim stopped"
    else
        echo "net-shim not running"
    fi
}

load_rc_config $name
: ${netshim_enable:="NO"}

run_rc_command "$1"
EOF

chmod +x "${RC_PATH}"

# 3. Enable service
echo "==> Enabling service..."
sysrc netshim_enable=YES >/dev/null

# 4. Start service
echo "==> Starting service..."
service netshim restart || service netshim start

echo "==> Install completed successfully"
echo "==> Logs: ${LOG_PATH}"
echo "==> Status: service netshim status"
