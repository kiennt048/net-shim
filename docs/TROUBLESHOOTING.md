# Net-Shim Troubleshooting Guide

**Common Issues and Solutions**

Version: 1.7.x

---

## Table of Contents

1. [Quick Diagnostics](#quick-diagnostics)
2. [Connection Issues](#connection-issues)
3. [Authentication Issues](#authentication-issues)
4. [Configuration Issues](#configuration-issues)
5. [Network Connectivity Issues](#network-connectivity-issues)
6. [Service Issues](#service-issues)
7. [Performance Issues](#performance-issues)
8. [Recovery Procedures](#recovery-procedures)
9. [Log Analysis](#log-analysis)
10. [Getting Help](#getting-help)

---

## Quick Diagnostics

### Smoke Test Script

Run this on pfSense to quickly identify issues:

```bash
#!/bin/sh
echo "=== Net-Shim Diagnostics ==="
echo ""

# 1. Service status
echo -n "1. Service running: "
if pgrep -x net-shim > /dev/null; then
    echo "YES (PID: $(pgrep -x net-shim))"
else
    echo "NO - Service not running!"
fi

# 2. Port listening
echo -n "2. Port 8080 listening: "
if sockstat -4 -l | grep -q ":8080"; then
    echo "YES"
else
    echo "NO - Port not open!"
fi

# 3. Health check (try HTTP first, then HTTPS)
echo -n "3. Health endpoint: "
HEALTH=$(curl -s --connect-timeout 3 http://127.0.0.1:8080/health 2>/dev/null)
if [ "$HEALTH" = "OK" ]; then
    echo "OK (HTTP)"
else
    HEALTH=$(curl -sk --connect-timeout 3 https://127.0.0.1:8443/health 2>/dev/null)
    if [ "$HEALTH" = "OK" ]; then
        echo "OK (HTTPS)"
    else
        echo "FAILED"
    fi
fi

# 4. Default route
echo -n "4. Default route: "
GW=$(netstat -rn | grep "^default\|^0.0.0.0" | awk '{print $2}' | head -1)
if [ -n "$GW" ]; then
    echo "YES ($GW)"
else
    echo "NO - No default route!"
fi

# 5. NAT rules
echo -n "5. NAT rules loaded: "
if pfctl -sn 2>/dev/null | grep -q "nat on"; then
    echo "YES"
else
    echo "NO - NAT not configured!"
fi

# 6. Filter rules
echo -n "6. Filter rules loaded: "
if pfctl -sr 2>/dev/null | grep -q "pass"; then
    echo "YES"
else
    echo "NO - Filter rules missing!"
fi

# 7. Gateway ping
echo -n "7. Gateway reachable: "
if [ -n "$GW" ] && ping -c 1 -t 2 $GW > /dev/null 2>&1; then
    echo "YES"
else
    echo "NO - Cannot reach gateway!"
fi

# 8. Internet connectivity
echo -n "8. Internet (8.8.8.8): "
if ping -c 1 -t 2 8.8.8.8 > /dev/null 2>&1; then
    echo "YES"
else
    echo "NO - No internet!"
fi

echo ""
echo "=== End Diagnostics ==="
```

---

## Connection Issues

### Cannot Access Web Interface

**Symptoms:**
- Browser shows "Connection refused"
- Browser shows "Timed out"

**Solutions:**

1. **Check if service is running:**
   ```bash
   pgrep net-shim
   # If no output, service is not running
   service netshim start
   ```

2. **Check port is listening:**
   ```bash
   sockstat -4 -l | grep 8443
   # Should show net-shim listening on 8443
   ```

3. **Test from localhost:**
   ```bash
   curl -k https://127.0.0.1:8443/health
   # Should return "OK"
   ```

4. **Check firewall rules:**
   ```bash
   pfctl -sr | grep 8443
   # If no rules, add via pfSense GUI
   ```

5. **Check interface binding:**
   ```bash
   # Net-shim binds to 0.0.0.0:8443 (all interfaces)
   netstat -an | grep 8443
   ```

---

### Certificate Warning in Browser

**Symptoms:**
- Browser shows "Your connection is not private"
- NET::ERR_CERT_AUTHORITY_INVALID

**Solutions:**

1. **This is expected** - Net-Shim uses a self-signed certificate

2. **Proceed anyway:**
   - Chrome: Click "Advanced" → "Proceed to site"
   - Firefox: Click "Advanced" → "Accept the Risk"
   - Safari: Click "Show Details" → "Visit this website"

3. **Use custom certificate:**
   ```bash
   # Replace with trusted certificates
   cp your-cert.crt /usr/local/share/netshim/server.crt
   cp your-key.key /usr/local/share/netshim/server.key
   chmod 600 /usr/local/share/netshim/server.key
   service netshim restart
   ```

---

### HTTP Redirect Not Working

**Symptoms:**
- http://IP:8080 doesn't redirect to HTTPS

**Solutions:**

1. **Check HTTP server is running:**
   ```bash
   sockstat -4 -l | grep 8080
   ```

2. **Test redirect:**
   ```bash
   curl -I http://127.0.0.1:8080/
   # Should show 301 redirect to https
   ```

---

## Authentication Issues

### Cannot Login - Invalid Credentials

**Symptoms:**
- "Invalid username or password" error
- Correct pfSense credentials not working

**Solutions:**

1. **Verify credentials in pfSense:**
   - Login to pfSense WebGUI (port 443)
   - Confirm credentials work there

2. **Check user exists:**
   ```bash
   grep -A5 "<user>" /cf/conf/config.xml | head -20
   ```

3. **Reset admin password via console:**
   - Connect to pfSense console
   - Option 3: Reset webConfigurator password

---

### Session Expired

**Symptoms:**
- Redirected to login unexpectedly
- "Session expired" message

**Solutions:**

1. **Sessions expire after 24 hours** - This is normal

2. **Check browser cookies:**
   - Clear cookies and login again
   - Ensure cookies are enabled

3. **Check system time:**
   ```bash
   date
   # If time is wrong, sessions may expire incorrectly
   ```

---

### CSRF Validation Failed

**Symptoms:**
- "Security validation failed" error
- Form submission rejected

**Solutions:**

1. **Refresh the page and try again**
   - CSRF tokens are single-use

2. **Check browser JavaScript:**
   - Ensure JavaScript is enabled
   - Clear browser cache

3. **Multiple tabs issue:**
   - Using multiple tabs can cause token conflicts
   - Submit from only one tab

---

## Configuration Issues

### Configuration Not Applied

**Symptoms:**
- Changes don't take effect
- Interface shows old settings

**Solutions:**

1. **Check for errors in log:**
   ```bash
   grep "NetShim" /var/log/system.log | tail -20
   ```

2. **Manually reload filter:**
   ```bash
   /etc/rc.filter_configure_sync
   ```

3. **Verify config was saved:**
   ```bash
   grep "Updated" /var/log/system.log | tail -5
   ```

---

### PPPoE Not Connecting

**Symptoms:**
- WAN shows "PPPoE" but no IP
- Connection timeout

**Solutions:**

1. **Verify credentials:**
   - Check username format (may need @domain)
   - Verify password is correct

2. **Check VLAN requirement:**
   - Many ISPs require VLAN tagging (e.g., VLAN 35)
   - Enable VLAN and set correct ID

3. **Check physical connection:**
   ```bash
   ifconfig em0  # Check physical interface
   # Should show "status: active"
   ```

4. **Check PPP status:**
   ```bash
   ifconfig pppoe0
   # Should show IP if connected
   ```

5. **View PPP logs:**
   ```bash
   grep ppp /var/log/system.log | tail -20
   ```

---

### DHCP Server Not Working

**Symptoms:**
- Clients not receiving IP addresses
- "No DHCP offers received"

**Solutions:**

1. **Ensure interface is in Static mode first:**
   - DHCP server requires static IP on interface

2. **Check DHCP service:**
   ```bash
   ps aux | grep kea
   # or
   ps aux | grep dhcpd
   ```

3. **Restart DHCP service:**
   ```bash
   /usr/local/etc/rc.d/kea restart
   # or
   /usr/local/sbin/dhcpd restart
   ```

4. **Check DHCP pool range:**
   - Pool must be within interface subnet
   - Pool must not include interface IP

---

## Network Connectivity Issues

### LAN Cannot Access Internet

**Symptoms:**
- LAN clients can ping pfSense
- LAN clients cannot ping 8.8.8.8

**Solutions:**

1. **Check NAT rules:**
   ```bash
   pfctl -sn | head -20
   # Should show "nat on em0" (or WAN interface)
   ```

2. **Check routing:**
   ```bash
   netstat -rn | grep default
   # Should show default route via WAN gateway
   ```

3. **Check filter rules:**
   ```bash
   pfctl -sr | grep "pass in"
   # Should show pass rules for LAN
   ```

4. **Force reload:**
   ```bash
   /etc/rc.filter_configure_sync
   ```

5. **Check WAN connectivity:**
   ```bash
   # From pfSense
   ping -c 3 8.8.8.8
   ```

---

### Cannot Ping WAN IP from LAN

**Symptoms:**
- Can access internet
- Cannot ping WAN interface IP from LAN

**Solutions:**

1. **Check firewall rules:**
   ```bash
   pfctl -sr | grep icmp
   ```

2. **This may be expected:**
   - Some configurations block LAN → WAN interface traffic
   - Add explicit rule if needed

---

### Configuration Breaks Connectivity

**Symptoms:**
- After applying config, network stops working
- Was working before net-shim change

**Solutions:**

1. **Immediate fix from console:**
   ```bash
   /etc/rc.filter_configure_sync
   ```

2. **Restore previous config:**
   ```bash
   # Backups are in /cf/conf/backup/
   ls -la /cf/conf/backup/
   cp /cf/conf/backup/config-XXXXXX.xml /cf/conf/config.xml
   /etc/rc.reload_all
   ```

3. **Factory reset via console:**
   - Connect to pfSense console
   - Option 4: Reset to factory defaults

---

### WAN Gets IP but No Internet

**Symptoms:**
- WAN interface has IP address
- Cannot reach internet from pfSense itself

**Solutions:**

1. **Check gateway:**
   ```bash
   netstat -rn | grep default
   ping -c 3 <gateway-ip>
   ```

2. **Check DNS:**
   ```bash
   cat /etc/resolv.conf
   nslookup google.com
   ```

3. **Check upstream device:**
   - Verify ISP modem is online
   - Check for MAC filtering on modem

---

## Service Issues

### Service Won't Start

**Symptoms:**
- `service netshim start` shows no errors but service not running

**Solutions:**

1. **Check binary exists:**
   ```bash
   ls -la /usr/local/bin/net-shim
   file /usr/local/bin/net-shim
   # Should show FreeBSD executable
   ```

2. **Check permissions:**
   ```bash
   chmod +x /usr/local/bin/net-shim
   ```

3. **Run manually to see errors:**
   ```bash
   /usr/local/bin/net-shim
   ```

4. **Check for port conflict:**
   ```bash
   sockstat -4 -l | grep -E "8443|8080"
   ```

---

### Service Crashes

**Symptoms:**
- Service stops unexpectedly
- Need to restart frequently

**Solutions:**

1. **Check system logs:**
   ```bash
   grep -i "net-shim\|panic\|fatal" /var/log/system.log
   ```

2. **Check memory:**
   ```bash
   top -b | head -20
   ```

3. **Update to latest version:**
   - Crashes may be fixed in newer versions

---

### High CPU Usage

**Symptoms:**
- net-shim using high CPU
- System slow

**Solutions:**

1. **Check process:**
   ```bash
   top -b | grep net-shim
   ```

2. **Restart service:**
   ```bash
   service netshim restart
   ```

3. **Check for loops:**
   - Rapid page refreshes can cause issues
   - Check for automated scripts hitting the API

---

## Performance Issues

### Slow Page Load

**Symptoms:**
- Dashboard takes long to load
- Stats slow to update

**Solutions:**

1. **Check PHP execution:**
   ```bash
   time /usr/local/bin/php -r "require_once('config.inc'); echo 'OK';"
   # Should complete in < 1 second
   ```

2. **Check config.xml size:**
   ```bash
   ls -lh /cf/conf/config.xml
   # Very large configs (>10MB) may be slow
   ```

3. **Check system load:**
   ```bash
   uptime
   top -b | head -10
   ```

---

## Recovery Procedures

### Emergency Access via Console

If locked out of web interface:

1. Connect to console (serial/keyboard+monitor)
2. Login as admin
3. Check/fix net-shim:
   ```bash
   service netshim status
   service netshim restart
   ```

---

### Restore from Backup

```bash
# List available backups
ls -la /cf/conf/backup/

# Restore specific backup
cp /cf/conf/backup/config-YYYYMMDDHHMMSS.xml /cf/conf/config.xml

# Reload configuration
/etc/rc.reload_all
```

---

### Factory Reset

**Via Net-Shim:**
1. Go to Backup & Restore
2. Click "Reset to Defaults"
3. Reboot when prompted

**Via Console:**
1. Connect to console
2. Select option 4: Reset to factory defaults
3. Confirm and wait for reboot

**Via Command Line:**
```bash
/usr/local/bin/net-shim --init
reboot
```

---

### Complete Reinstall

```bash
# Stop service
service netshim stop

# Remove old binary
rm /usr/local/bin/net-shim

# Copy new binary
scp new-net-shim root@pfSense:/usr/local/bin/net-shim

# Set permissions
chmod +x /usr/local/bin/net-shim

# Start service
service netshim start
```

---

## Log Analysis

### View Net-Shim Logs

```bash
# Recent entries
grep "NetShim" /var/log/system.log | tail -50

# All entries
grep "NetShim" /var/log/system.log

# Real-time monitoring
tail -f /var/log/system.log | grep -i netshim
```

### Common Log Messages

| Message | Meaning |
|---------|---------|
| `Configuration applied successfully` | Config change worked |
| `Outbound NAT set to automatic mode` | NAT configured |
| `Enabled $interface` | Interface enabled |
| `Disabled $interface` | Interface disabled |
| `Configuration restore completed` | Backup restored |
| `Factory reset completed` | Reset to defaults |

### Error Log Messages

| Message | Meaning | Solution |
|---------|---------|----------|
| `CSRF validation failed` | Invalid/expired token | Refresh page |
| `Config apply failed` | PHP script error | Check config values |
| `Interface toggle failed` | Cannot change interface | Check interface exists |
| `Backup download failed` | Cannot read config | Check permissions |

---

## Getting Help

### Information to Collect

Before seeking help, gather:

1. **Net-Shim version:**
   ```bash
   curl -sk https://127.0.0.1:8443/version
   ```

2. **pfSense version:**
   ```bash
   cat /etc/version
   ```

3. **Error messages:**
   ```bash
   grep "NetShim" /var/log/system.log | tail -50
   ```

4. **Diagnostic output:**
   ```bash
   # Run smoke test script from above
   ```

5. **Network state:**
   ```bash
   ifconfig -a
   netstat -rn
   pfctl -sr | head -30
   pfctl -sn | head -20
   ```

### Support Channels

- GitHub Issues: https://github.com/anthropics/claude-code/issues
- Documentation: See other docs in /docs folder

---

## Quick Reference

### Essential Commands

| Task | Command |
|------|---------|
| Start service | `service netshim start` |
| Stop service | `service netshim stop` |
| Restart service | `service netshim restart` |
| Check status | `service netshim status` |
| View logs | `grep NetShim /var/log/system.log` |
| Reload filter | `/etc/rc.filter_configure_sync` |
| Reload all | `/etc/rc.reload_all` |
| Check routing | `netstat -rn` |
| Check NAT | `pfctl -sn` |
| Check filter | `pfctl -sr` |
| Check states | `pfctl -ss` |

---

*Troubleshooting Guide - Net-Shim v1.7.x*
