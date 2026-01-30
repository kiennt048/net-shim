# Net-Shim Installation Guide

**Deployment & Installation Instructions**

Version: 1.7.x | pfSense 2.8.x Compatible

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Install](#quick-install)
3. [Manual Installation](#manual-installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Upgrading](#upgrading)
7. [Uninstallation](#uninstallation)
8. [Troubleshooting Installation](#troubleshooting-installation)

---

## Prerequisites

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| pfSense Version | 2.7.x | 2.8.x |
| FreeBSD Version | 14.x | 16.x |
| RAM | 512 MB | 1 GB |
| Disk Space | 20 MB | 50 MB |
| Architecture | amd64 | amd64 |

### Network Requirements

| Port | Protocol | Purpose |
|------|----------|---------|
| 8443 | TCP/HTTPS | Web interface |
| 8080 | TCP/HTTP | Redirect to HTTPS |

### Access Requirements

- SSH access to pfSense (or console access)
- Root privileges on pfSense
- SCP/SFTP capability for file transfer

---

## Quick Install

### Option 1: Using Install Script (Recommended)

From your local machine:

```bash
# 1. Copy files to pfSense
scp net-shim install.sh root@<PFSENSE_IP>:/tmp/

# 2. SSH into pfSense
ssh root@<PFSENSE_IP>

# 3. Run installer
chmod +x /tmp/install.sh
/tmp/install.sh
```

### Option 2: One-Line Install

From pfSense console or SSH:

```bash
cd /tmp && fetch https://your-server/net-shim && fetch https://your-server/install.sh && chmod +x install.sh && ./install.sh
```

---

## Manual Installation

### Step 1: Build the Binary

On your development machine:

```bash
# Clone or navigate to source
cd /path/to/net-shim

# Build for pfSense (FreeBSD/amd64)
make build

# Verify build
ls -la net-shim
```

### Step 2: Transfer to pfSense

```bash
# Using SCP
scp net-shim root@<PFSENSE_IP>:/usr/local/bin/

# Or using SFTP
sftp root@<PFSENSE_IP>
put net-shim /usr/local/bin/
```

### Step 3: Set Permissions

On pfSense:

```bash
# Make executable
chmod +x /usr/local/bin/net-shim

# Verify
ls -la /usr/local/bin/net-shim
```

### Step 4: Create RC Script

Create `/usr/local/etc/rc.d/netshim`:

```bash
cat > /usr/local/etc/rc.d/netshim << 'EOF'
#!/bin/sh
#
# PROVIDE: netshim
# REQUIRE: NETWORKING
# KEYWORD: shutdown
#
# Add these lines to /etc/rc.conf to enable netshim:
#
# netshim_enable="YES"
#

. /etc/rc.subr

name="netshim"
rcvar="netshim_enable"

load_rc_config $name

: ${netshim_enable:="NO"}
: ${netshim_user:="root"}
: ${netshim_pidfile:="/var/run/netshim.pid"}

pidfile="${netshim_pidfile}"
command="/usr/local/bin/net-shim"
command_args="&"

start_cmd="${name}_start"
stop_cmd="${name}_stop"
status_cmd="${name}_status"

netshim_start()
{
    echo "Starting ${name}."
    /usr/sbin/daemon -p ${pidfile} -f ${command}
}

netshim_stop()
{
    if [ -f ${pidfile} ]; then
        echo "Stopping ${name}."
        kill $(cat ${pidfile}) 2>/dev/null
        rm -f ${pidfile}
    else
        echo "${name} is not running."
    fi
}

netshim_status()
{
    if [ -f ${pidfile} ] && kill -0 $(cat ${pidfile}) 2>/dev/null; then
        echo "${name} is running as pid $(cat ${pidfile})."
    else
        echo "${name} is not running."
        return 1
    fi
}

run_rc_command "$1"
EOF
```

### Step 5: Set RC Script Permissions

```bash
chmod +x /usr/local/etc/rc.d/netshim
```

### Step 6: Enable Service

```bash
# Add to rc.conf
echo 'netshim_enable="YES"' >> /etc/rc.conf

# Or edit manually
vi /etc/rc.conf
# Add: netshim_enable="YES"
```

### Step 7: Start Service

```bash
service netshim start

# Verify running
service netshim status

# Check logs
ps aux | grep net-shim
```

### Step 8: Verify Installation

```bash
# Health check
curl -k https://127.0.0.1:8443/health

# Or from browser
# https://<PFSENSE_IP>:8443
```

---

## Configuration

### Default Ports

| Service | Port | Protocol | Notes |
|---------|------|----------|-------|
| HTTP | 8080 | TCP | Always available |
| HTTPS | 8443 | TCP | Only if TLS succeeds |

> **Note:** If TLS certificate generation fails (e.g., directory permissions), the app runs on HTTP port 8080 only.

### TLS Certificates

Net-Shim attempts to generate self-signed certificates on first run.

**Certificate Location:**
```
/usr/local/share/netshim/server.crt
/usr/local/share/netshim/server.key
```

**To enable HTTPS manually:**

```bash
# Create directory
mkdir -p /usr/local/share/netshim
chmod 700 /usr/local/share/netshim

# Restart to generate certs
service netshim restart
```

**To use custom certificates:**

```bash
# Replace with your certificates
cp your-cert.crt /usr/local/share/netshim/server.crt
cp your-key.key /usr/local/share/netshim/server.key
chmod 600 /usr/local/share/netshim/server.key

# Restart service
service netshim restart
```

### Firewall Rules

If you need to access Net-Shim from WAN or other interfaces, add firewall rules:

**Via pfSense WebGUI:**
1. Firewall → Rules → [Interface]
2. Add rule: Pass TCP to (this firewall) port 8443
3. Apply changes

**Via config.xml (advanced):**
```xml
<rule>
    <type>pass</type>
    <interface>wan</interface>
    <ipprotocol>inet</ipprotocol>
    <protocol>tcp</protocol>
    <destination>
        <any></any>
        <port>8443</port>
    </destination>
    <descr>Allow Net-Shim access</descr>
</rule>
```

---

## Service Management

### Start/Stop/Restart

```bash
# Start
service netshim start

# Stop
service netshim stop

# Restart
service netshim restart

# Status
service netshim status
```

### Manual Start (Debugging)

```bash
# Stop service first
service netshim stop

# Run in foreground (see logs)
/usr/local/bin/net-shim

# Run with init mode (factory reset)
/usr/local/bin/net-shim --init
```

### View Logs

```bash
# Recent syslog entries
grep netshim /var/log/system.log | tail -50

# Or use clog (if available)
clog /var/log/system.log | grep -i netshim

# Real-time monitoring
tail -f /var/log/system.log | grep -i netshim
```

### Process Management

```bash
# Check if running
pgrep net-shim

# Kill all instances
pkill net-shim

# Force kill
pkill -9 net-shim
```

---

## Upgrading

### Standard Upgrade

```bash
# 1. Stop service
service netshim stop

# 2. Backup current binary
cp /usr/local/bin/net-shim /usr/local/bin/net-shim.bak

# 3. Copy new binary
scp new-net-shim root@<PFSENSE_IP>:/usr/local/bin/net-shim

# 4. Set permissions
chmod +x /usr/local/bin/net-shim

# 5. Start service
service netshim start

# 6. Verify
curl -k https://127.0.0.1:8443/version
```

### Rollback

```bash
# Stop service
service netshim stop

# Restore backup
cp /usr/local/bin/net-shim.bak /usr/local/bin/net-shim

# Start service
service netshim start
```

### Zero-Downtime Upgrade

```bash
# 1. Copy new binary with different name
scp net-shim root@<PFSENSE_IP>:/usr/local/bin/net-shim.new

# 2. Make executable
ssh root@<PFSENSE_IP> "chmod +x /usr/local/bin/net-shim.new"

# 3. Atomic replace and restart
ssh root@<PFSENSE_IP> "mv /usr/local/bin/net-shim.new /usr/local/bin/net-shim && service netshim restart"
```

---

## Uninstallation

### Complete Removal

```bash
# 1. Stop and disable service
service netshim stop
sed -i '' '/netshim_enable/d' /etc/rc.conf

# 2. Remove files
rm -f /usr/local/bin/net-shim
rm -f /usr/local/bin/net-shim.bak
rm -f /usr/local/etc/rc.d/netshim

# 3. Remove certificates (optional)
rm -rf /usr/local/share/netshim/

# 4. Remove PID file
rm -f /var/run/netshim.pid
```

### Keep Configuration

If you want to reinstall later, keep the certificates:

```bash
# Stop and remove binary only
service netshim stop
rm -f /usr/local/bin/net-shim

# Certificates remain in /usr/local/share/netshim/
```

---

## Troubleshooting Installation

### Binary Won't Execute

```bash
# Check architecture
file /usr/local/bin/net-shim
# Should show: ELF 64-bit LSB executable, x86-64, FreeBSD

# Check permissions
ls -la /usr/local/bin/net-shim
# Should show: -rwxr-xr-x

# Try running manually
/usr/local/bin/net-shim
```

### Port Already in Use

```bash
# Check what's using port 8443
sockstat -4 -l | grep 8443

# Or
netstat -an | grep 8443
```

### Service Won't Start

```bash
# Check RC script
cat /usr/local/etc/rc.d/netshim

# Check rc.conf
grep netshim /etc/rc.conf

# Try manual start
/usr/local/bin/net-shim &

# Check for errors
ps aux | grep net-shim
```

### Can't Connect from Browser

1. **Check firewall rules:**
   ```bash
   pfctl -sr | grep 8443
   ```

2. **Check service is running:**
   ```bash
   curl -k https://127.0.0.1:8443/health
   ```

3. **Check from LAN:**
   ```bash
   # From LAN client
   curl -k https://<PFSENSE_LAN_IP>:8443/health
   ```

### Certificate Issues

```bash
# Regenerate certificates
rm -rf /usr/local/share/netshim/
service netshim restart

# Check certificate
openssl s_client -connect 127.0.0.1:8443 -showcerts
```

### PHP Errors

```bash
# Test PHP execution
/usr/local/bin/php -v

# Check PHP can load pfSense includes
/usr/local/bin/php -r "require_once('config.inc'); echo 'OK';"
```

---

## Security Hardening

### Restrict Access by IP

Add firewall rules to limit management access:

```bash
# Only allow from management network
# Via pfSense GUI: Firewall → Rules
# Source: Management_Network
# Destination: This Firewall, Port 8443
```

### Use Custom Certificates

Replace self-signed with trusted certificates:

```bash
# Use Let's Encrypt or commercial cert
cp fullchain.pem /usr/local/share/netshim/server.crt
cp privkey.pem /usr/local/share/netshim/server.key
chmod 600 /usr/local/share/netshim/server.key
service netshim restart
```

### Audit Logging

All actions are logged to syslog:

```bash
# View audit trail
grep "NetShim:" /var/log/system.log
```

---

## Post-Installation Checklist

- [ ] Binary installed at `/usr/local/bin/net-shim`
- [ ] RC script installed at `/usr/local/etc/rc.d/netshim`
- [ ] Service enabled in `/etc/rc.conf`
- [ ] Service running (`service netshim status`)
- [ ] Health check passes (`curl -k https://127.0.0.1:8443/health`)
- [ ] Web interface accessible from browser
- [ ] Login with pfSense credentials works
- [ ] Dashboard shows interfaces
- [ ] Test configuration change works
- [ ] Internet connectivity maintained after change

---

*Installation Guide - Net-Shim v1.7.x*
