# pfSense Development Guide

**Complete Reference for Building Applications on pfSense/FreeBSD**

Version: pfSense 2.7.x / 2.8.x | FreeBSD 14.x / 16.x

---

## Table of Contents

1. [Filesystem Structure](#filesystem-structure)
2. [Directory Persistence](#directory-persistence)
3. [Service Management](#service-management)
4. [Autostart Mechanisms](#autostart-mechanisms)
5. [PHP Integration](#php-integration)
6. [Configuration System](#configuration-system)
7. [Firewall (pf) Integration](#firewall-pf-integration)
8. [Network Functions](#network-functions)
9. [Logging & Syslog](#logging--syslog)
10. [User Authentication](#user-authentication)
11. [Web Server Integration](#web-server-integration)
12. [Package Development](#package-development)
13. [Useful Commands](#useful-commands)
14. [Common Pitfalls](#common-pitfalls)
15. [Best Practices](#best-practices)

---

## Filesystem Structure

### pfSense Directory Layout

```
/
├── bin/                    # Essential user binaries
├── boot/                   # Boot loader files
├── cf/                     # CompactFlash mount (persistent)
│   └── conf/              # ⭐ Configuration files (PERSISTENT)
│       ├── config.xml     # Main pfSense configuration
│       └── backup/        # Config backups
├── dev/                    # Device files
├── etc/                    # System configuration (mostly symlinks)
│   ├── rc.conf            # System startup config
│   ├── resolv.conf        # DNS (generated)
│   └── hosts              # Hosts file
├── home/                   # User home directories (empty usually)
├── lib/                    # Essential libraries
├── libexec/                # System daemons
├── mnt/                    # Mount points
├── proc/                   # Process filesystem
├── rescue/                 # Recovery tools
├── root/                   # ⭐ Root home directory (PERSISTENT)
├── sbin/                   # Essential system binaries
├── tmp/                    # ⚠️ Temporary files (RAM - CLEARED ON REBOOT)
├── usr/                    # ⭐ User programs (PERSISTENT)
│   ├── bin/               # User binaries
│   ├── lib/               # Libraries
│   ├── local/             # ⭐ Local installations (PERSISTENT)
│   │   ├── bin/           # Local binaries (your apps go here)
│   │   ├── etc/           # Local config files
│   │   │   └── rc.d/      # ⭐ RC scripts (autostart)
│   │   ├── lib/           # Local libraries
│   │   ├── libexec/       # Local daemons
│   │   ├── sbin/          # Local system binaries
│   │   ├── share/         # ⭐ Shared data (PERSISTENT)
│   │   │   └── pfSense/   # pfSense specific data
│   │   └── www/           # ⭐ pfSense WebGUI files
│   └── sbin/              # System binaries
└── var/                    # ⚠️ Variable data (RAM - CLEARED ON REBOOT)
    ├── db/                # ⚠️ Databases (RAM)
    ├── etc/               # ⚠️ Generated configs (RAM)
    ├── log/               # ⚠️ Log files (RAM - circular logs)
    ├── run/               # ⚠️ PID files, sockets (RAM)
    └── tmp/               # ⚠️ Temp files (RAM)
```

---

## Directory Persistence

### Persistent Directories (Survive Reboot)

| Directory | Purpose | Use For |
|-----------|---------|---------|
| `/cf/conf/` | pfSense config | Config files, backups |
| `/usr/local/bin/` | Local binaries | Your application binaries |
| `/usr/local/sbin/` | Local system binaries | System daemons |
| `/usr/local/etc/` | Local config | App configuration |
| `/usr/local/etc/rc.d/` | RC scripts | Autostart scripts |
| `/usr/local/share/` | Shared data | App data, certs, databases |
| `/usr/local/www/` | Web files | Web UI files |
| `/root/` | Root home | Scripts, dotfiles |

### Non-Persistent Directories (RAM - Cleared on Reboot)

| Directory | Purpose | Why RAM? |
|-----------|---------|----------|
| `/tmp/` | Temporary files | Performance, SSD wear |
| `/var/` | Variable data | Performance, SSD wear |
| `/var/db/` | Databases | Performance |
| `/var/etc/` | Generated configs | Regenerated on boot |
| `/var/log/` | Log files | Circular buffers |
| `/var/run/` | PID files, sockets | Runtime only |

### Memory Filesystem Details

pfSense uses memory-backed filesystems (md/tmpfs) for performance and to reduce SSD/CF card wear:

```bash
# Check mounted filesystems
mount | grep -E "tmpfs|md"

# Typical output:
# /dev/md0 on /tmp (ufs, local)
# /dev/md1 on /var (ufs, local)
```

### Recommended Locations for Your App

| Type | Location | Example |
|------|----------|---------|
| Binary | `/usr/local/bin/` | `/usr/local/bin/myapp` |
| RC Script | `/usr/local/etc/rc.d/` | `/usr/local/etc/rc.d/myapp` |
| Config | `/usr/local/etc/myapp/` | `/usr/local/etc/myapp/config.json` |
| Data | `/usr/local/share/myapp/` | `/usr/local/share/myapp/data.db` |
| Certs | `/usr/local/share/myapp/` | `/usr/local/share/myapp/server.crt` |
| Web UI | `/usr/local/www/myapp/` | `/usr/local/www/myapp/index.php` |
| Logs | Use syslog | `syslog(LOG_INFO, "message")` |
| PID | `/var/run/` | `/var/run/myapp.pid` |

---

## Service Management

### RC Script Template

Create `/usr/local/etc/rc.d/myapp`:

```sh
#!/bin/sh
#
# PROVIDE: myapp
# REQUIRE: NETWORKING DAEMON
# BEFORE: LOGIN
# KEYWORD: shutdown
#
# Add these lines to /etc/rc.conf.local or /etc/rc.conf to enable:
#
# myapp_enable="YES"
#

. /etc/rc.subr

name="myapp"
rcvar="myapp_enable"

load_rc_config $name

: ${myapp_enable:="NO"}
: ${myapp_user:="root"}
: ${myapp_pidfile:="/var/run/myapp.pid"}
: ${myapp_flags:=""}

pidfile="${myapp_pidfile}"
command="/usr/local/bin/myapp"
command_args="${myapp_flags}"

# Use daemon to background the process
start_cmd="${name}_start"
stop_cmd="${name}_stop"
status_cmd="${name}_status"
restart_cmd="${name}_restart"

myapp_start()
{
    if [ -f ${pidfile} ] && kill -0 $(cat ${pidfile}) 2>/dev/null; then
        echo "${name} is already running."
        return 1
    fi
    echo "Starting ${name}."
    /usr/sbin/daemon -p ${pidfile} -f ${command} ${command_args}
}

myapp_stop()
{
    if [ -f ${pidfile} ]; then
        echo "Stopping ${name}."
        kill $(cat ${pidfile}) 2>/dev/null
        rm -f ${pidfile}
    else
        echo "${name} is not running."
    fi
}

myapp_status()
{
    if [ -f ${pidfile} ] && kill -0 $(cat ${pidfile}) 2>/dev/null; then
        echo "${name} is running as pid $(cat ${pidfile})."
    else
        echo "${name} is not running."
        return 1
    fi
}

myapp_restart()
{
    myapp_stop
    sleep 1
    myapp_start
}

run_rc_command "$1"
```

### Enable Service

```bash
# Method 1: Add to rc.conf
echo 'myapp_enable="YES"' >> /etc/rc.conf

# Method 2: Add to rc.conf.local (preferred, survives upgrades)
echo 'myapp_enable="YES"' >> /etc/rc.conf.local

# Method 3: Use sysrc command
sysrc myapp_enable="YES"
```

### Service Commands

```bash
# Start/Stop/Restart
service myapp start
service myapp stop
service myapp restart
service myapp status

# One-shot start (ignore enable status)
service myapp onestart
service myapp onestop

# List all services
service -e

# Check if enabled
service myapp enabled && echo "Enabled" || echo "Disabled"
```

---

## Autostart Mechanisms

### 1. RC Script (Recommended)

See [Service Management](#service-management) above.

### 2. shellcmd / earlyshellcmd

Via pfSense WebGUI or config.xml:

```xml
<system>
    <!-- Runs early in boot, before most services -->
    <earlyshellcmd>/usr/local/bin/myapp --early-init</earlyshellcmd>

    <!-- Runs after system is up -->
    <shellcmd>/usr/local/bin/myapp --start</shellcmd>
</system>
```

**Via WebGUI:**
- Diagnostics → Edit File → `/cf/conf/config.xml`
- Or install "Shellcmd" package

### 3. Cron Jobs

Via config.xml:

```xml
<cron>
    <item>
        <minute>*/5</minute>
        <hour>*</hour>
        <mday>*</mday>
        <month>*</month>
        <wday>*</wday>
        <who>root</who>
        <command>/usr/local/bin/myapp --check</command>
    </item>
</cron>
```

### 4. PHP Hooks

In custom PHP code:

```php
// Register a function to run after filter reload
register_shutdown_function('my_cleanup_function');

// Hook into config write
function my_config_hook() {
    // Called when config is saved
}
```

### Boot Sequence Order

```
1. Kernel loads
2. /etc/rc runs
3. earlyshellcmd commands run
4. Network interfaces configured
5. Routing configured
6. /usr/local/etc/rc.d/* services start (alphabetically)
7. shellcmd commands run
8. Login prompt appears
```

---

## PHP Integration

### pfSense PHP Includes

```php
<?php
// Essential includes
require_once("config.inc");        // Configuration access ($config array)
require_once("globals.inc");       // Global variables
require_once("functions.inc");     // Common functions
require_once("util.inc");          // Utility functions

// Network includes
require_once("interfaces.inc");    // Interface functions
require_once("filter.inc");        // Firewall functions
require_once("shaper.inc");        // Traffic shaping
require_once("rrd.inc");           // RRD graphing

// Service includes
require_once("services.inc");      // Service management
require_once("vpn.inc");           // VPN functions
require_once("openvpn.inc");       // OpenVPN specific
require_once("ipsec.inc");         // IPsec specific

// System includes
require_once("system.inc");        // System functions
require_once("auth.inc");          // Authentication
require_once("notices.inc");       // Notice system
require_once("pkg-utils.inc");     // Package utilities
```

### Configuration Access

```php
<?php
require_once("config.inc");

// Access global config
global $config;

// Read values
$hostname = $config['system']['hostname'];
$interfaces = $config['interfaces'];
$wan_ip = $config['interfaces']['wan']['ipaddr'];

// Modify config
$config['system']['hostname'] = 'new-hostname';

// Save config (IMPORTANT: always use write_config)
write_config("Changed hostname via my script");
```

### Common pfSense Functions

```php
<?php
// ===== CONFIGURATION =====
write_config("Description");              // Save config.xml
parse_config(true);                        // Reload config
backup_config();                           // Create backup

// ===== INTERFACES =====
interface_configure($interface);           // Configure single interface
interfaces_configure();                    // Configure all interfaces
get_interface_info($interface);            // Get interface details
get_interface_ip($interface);              // Get interface IP
get_interface_subnet($interface);          // Get subnet
get_real_interface($interface);            // Get physical interface name

// ===== ROUTING =====
system_routing_configure();                // Reload routing table
get_default_gateway();                     // Get default gateway

// ===== FIREWALL =====
filter_configure();                        // Reload filter rules
filter_configure_sync();                   // Sync reload (waits for completion)
get_configured_interface_with_descr();     // Get interfaces for rules

// ===== NAT =====
nat_rules_configure();                     // Configure NAT rules

// ===== SERVICES =====
services_dhcpd_configure();               // Restart DHCP server
services_dnsmasq_configure();             // Restart DNS forwarder
services_unbound_configure();             // Restart DNS resolver

// ===== GATEWAY =====
setup_gateways_monitor();                 // Restart gateway monitoring
return_gateways_status();                 // Get gateway status

// ===== DNS =====
system_resolvconf_generate();             // Regenerate resolv.conf
system_hostname_configure();              // Set hostname

// ===== SYSTEM =====
system_reboot();                          // Reboot system
system_halt();                            // Shutdown system
mwexec($command);                         // Execute shell command
mwexec_bg($command);                      // Execute in background

// ===== LOGGING =====
log_error("Error message");               // Log to system log
write_log("Message");                     // Write to log
syslog(LOG_INFO, "Message");             // Direct syslog
```

### Execute PHP from Shell

```bash
# Run PHP code directly
/usr/local/bin/php -r "require_once('config.inc'); print_r(\$config['system']);"

# Run PHP script
/usr/local/bin/php /path/to/script.php

# Run with pfSense context (from www directory)
cd /usr/local/www && /usr/local/bin/php script.php
```

---

## Configuration System

### config.xml Structure

```xml
<?xml version="1.0"?>
<pfsense>
    <version>24.0</version>

    <system>
        <hostname>pfSense</hostname>
        <domain>local</domain>
        <dns1>8.8.8.8</dns1>
        <webgui>
            <protocol>https</protocol>
            <port>443</port>
        </webgui>
        <ssh>
            <enable>enabled</enable>
            <port>22</port>
        </ssh>
        <user>...</user>
        <group>...</group>
    </system>

    <interfaces>
        <wan>
            <enable></enable>
            <if>em0</if>
            <ipaddr>dhcp</ipaddr>
            <descr>WAN</descr>
        </wan>
        <lan>
            <enable></enable>
            <if>em1</if>
            <ipaddr>192.168.1.1</ipaddr>
            <subnet>24</subnet>
            <descr>LAN</descr>
        </lan>
    </interfaces>

    <dhcpd>
        <lan>
            <enable></enable>
            <range>
                <from>192.168.1.100</from>
                <to>192.168.1.199</to>
            </range>
        </lan>
    </dhcpd>

    <nat>
        <outbound>
            <mode>automatic</mode>
        </outbound>
        <rule>...</rule>
    </nat>

    <filter>
        <rule>...</rule>
    </filter>

    <gateways>
        <gateway_item>...</gateway_item>
    </gateways>

    <staticroutes>
        <route>...</route>
    </staticroutes>

    <aliases>
        <alias>...</alias>
    </aliases>

    <installedpackages>
        <package>...</package>
    </installedpackages>
</pfsense>
```

### Config File Locations

| File | Purpose |
|------|---------|
| `/cf/conf/config.xml` | Main configuration |
| `/cf/conf/backup/` | Automatic backups |
| `/cf/conf/config.cache` | Parsed config cache |
| `/cf/conf/trigger_initial_wizard` | First-boot wizard trigger |
| `/cf/conf/enableserial_force` | Force serial console |

### Config Modification Best Practices

```php
<?php
require_once("config.inc");

global $config;

// 1. Always check if section exists
if (!isset($config['mysection'])) {
    $config['mysection'] = array();
}

// 2. Modify config
$config['mysection']['setting'] = 'value';

// 3. Always use write_config with description
write_config("MyApp: Changed setting to value");

// 4. Apply changes if needed
filter_configure_sync();
```

---

## Firewall (pf) Integration

### pf Commands

```bash
# View rules
pfctl -sr                    # Show filter rules
pfctl -sn                    # Show NAT rules
pfctl -sa                    # Show everything
pfctl -ss                    # Show state table
pfctl -si                    # Show statistics

# Manage rules
pfctl -f /tmp/rules.debug    # Load rules from file
pfctl -d                     # Disable firewall
pfctl -e                     # Enable firewall

# Tables
pfctl -t mytable -T show     # Show table contents
pfctl -t mytable -T add 1.2.3.4    # Add to table
pfctl -t mytable -T delete 1.2.3.4 # Remove from table
pfctl -t mytable -T flush    # Clear table

# States
pfctl -k host 1.2.3.4        # Kill states for host
pfctl -F states              # Flush all states
```

### PHP Firewall Functions

```php
<?php
require_once("filter.inc");

// Reload all rules
filter_configure();

// Sync reload (waits for completion)
filter_configure_sync();

// Get current rules
$rules = filter_generate_rules();

// Add to pf table
exec("/sbin/pfctl -t blocklist -T add 1.2.3.4");

// Kill states for IP
exec("/sbin/pfctl -k 1.2.3.4");
```

### Rule Structure in config.xml

```xml
<filter>
    <rule>
        <id></id>
        <tracker>1234567890</tracker>
        <type>pass</type>
        <interface>lan</interface>
        <ipprotocol>inet</ipprotocol>
        <protocol>tcp</protocol>
        <source>
            <any></any>
        </source>
        <destination>
            <network>wan</network>
            <port>80</port>
        </destination>
        <descr>Allow HTTP out</descr>
    </rule>
</filter>
```

---

## Network Functions

### Interface Management

```php
<?php
require_once("interfaces.inc");

// Configure single interface
interface_configure("lan", true);   // (interface, reload)

// Configure all interfaces
interfaces_configure();

// Get interface info
$info = get_interface_info("lan");
// Returns: ipaddr, subnet, status, mac, etc.

// Get IP address
$ip = get_interface_ip("lan");

// Get subnet
$subnet = get_interface_subnet("lan");

// Get physical interface name
$real = get_real_interface("lan");  // Returns "em1"

// Get all interfaces with descriptions
$interfaces = get_configured_interface_with_descr();
// Returns: array("wan" => "WAN", "lan" => "LAN", ...)
```

### Routing

```php
<?php
// Reload routing
system_routing_configure();

// Get routing table
exec("/usr/bin/netstat -rn", $routes);

// Get default gateway
$gateway = get_default_gateway();
```

### DHCP

```php
<?php
require_once("services.inc");

// Reconfigure DHCP server
services_dhcpd_configure();

// Get DHCP leases
$leases = system_get_dhcpleases();
```

---

## Logging & Syslog

### Syslog in PHP

```php
<?php
// Open syslog
openlog("myapp", LOG_PID | LOG_PERROR, LOG_LOCAL0);

// Log messages
syslog(LOG_INFO, "Information message");
syslog(LOG_WARNING, "Warning message");
syslog(LOG_ERR, "Error message");
syslog(LOG_DEBUG, "Debug message");

// Close syslog
closelog();

// Or use pfSense function
log_error("Error message");      // Logs to system.log
```

### Log Files

| Log | Location | Purpose |
|-----|----------|---------|
| System | `/var/log/system.log` | General system messages |
| Filter | `/var/log/filter.log` | Firewall logs |
| DHCP | `/var/log/dhcpd.log` | DHCP server logs |
| Auth | `/var/log/auth.log` | Authentication logs |
| VPN | `/var/log/vpn.log` | VPN logs |
| Resolver | `/var/log/resolver.log` | DNS resolver logs |
| Wireless | `/var/log/wireless.log` | WiFi logs |
| NTP | `/var/log/ntpd.log` | Time sync logs |
| PPP | `/var/log/ppp.log` | PPP/PPPoE logs |
| Routing | `/var/log/routing.log` | Routing daemon logs |
| Gateways | `/var/log/gateways.log` | Gateway monitor logs |

### View Logs

```bash
# View log (logs are circular/clog format)
clog /var/log/system.log

# Follow log
clog -f /var/log/system.log

# If clog not available
cat /var/log/system.log

# Filter logs
clog /var/log/system.log | grep myapp

# Tail logs
tail -f /var/log/system.log
```

---

## User Authentication

### Authenticate Against pfSense Users

```php
<?php
require_once("auth.inc");

// Authenticate user
$authcfg = auth_get_authserver("Local Database");
$authenticated = authenticate_user($username, $password, $authcfg);

if ($authenticated) {
    echo "Login successful";
} else {
    echo "Login failed";
}

// Check user privileges
$user = getUserEntry($username);
if (userHasPrivilege($user, "page-all")) {
    echo "User is admin";
}
```

### User Structure in config.xml

```xml
<system>
    <user>
        <name>admin</name>
        <descr>System Administrator</descr>
        <scope>system</scope>
        <uid>0</uid>
        <bcrypt-hash>$2y$10$...</bcrypt-hash>
        <priv>user-shell-access</priv>
    </user>
    <group>
        <name>admins</name>
        <gid>1999</gid>
        <member>0</member>
        <priv>page-all</priv>
    </group>
</system>
```

---

## Web Server Integration

### pfSense WebGUI Structure

```
/usr/local/www/
├── index.php              # Main page
├── head.inc               # HTML header
├── foot.inc               # HTML footer
├── guiconfig.inc          # GUI configuration
├── *.php                  # Page files
├── classes/               # PHP classes
├── css/                   # Stylesheets
├── javascript/            # JavaScript files
└── widgets/               # Dashboard widgets
```

### Creating a WebGUI Page

```php
<?php
// /usr/local/www/mypage.php

require_once("guiconfig.inc");

$pgtitle = array("My Section", "My Page");
include("head.inc");

// Your page content here
?>

<div class="panel panel-default">
    <div class="panel-heading">
        <h2 class="panel-title">My Page</h2>
    </div>
    <div class="panel-body">
        <p>Hello from my custom page!</p>
    </div>
</div>

<?php
include("foot.inc");
?>
```

### Running Separate Web Server

For custom apps, run your own web server on a different port:

```go
// Example: Run on port 8080
http.ListenAndServe("0.0.0.0:8080", handler)
```

**Important:** Don't conflict with pfSense ports:
- 80/443 - pfSense WebGUI (if using HTTP redirect)
- 22 - SSH

---

## Package Development

### Package Structure

```
/usr/local/pkg/mypackage/
├── mypackage.inc          # PHP functions
├── mypackage.xml          # Package definition
└── mypackage_install.inc  # Install/uninstall hooks
```

### Package XML

```xml
<?xml version="1.0" encoding="utf-8" ?>
<packagegui>
    <name>mypackage</name>
    <title>My Package</title>
    <version>1.0</version>
    <include_file>/usr/local/pkg/mypackage/mypackage.inc</include_file>

    <menu>
        <name>My Package</name>
        <section>Services</section>
        <url>/pkg_edit.php?xml=mypackage.xml</url>
    </menu>

    <service>
        <name>mypackage</name>
        <rcfile>mypackage.sh</rcfile>
        <executable>mypackage</executable>
    </service>

    <tabs>
        <tab>
            <text>Settings</text>
            <url>/pkg_edit.php?xml=mypackage.xml</url>
            <active/>
        </tab>
    </tabs>

    <fields>
        <field>
            <name>enable</name>
            <type>checkbox</type>
            <description>Enable My Package</description>
        </field>
        <field>
            <name>server</name>
            <type>input</type>
            <description>Server address</description>
        </field>
    </fields>
</packagegui>
```

---

## Useful Commands

### System Information

```bash
# pfSense version
cat /etc/version

# FreeBSD version
freebsd-version

# Uptime
uptime

# Memory usage
top -b | head -5

# Disk usage
df -h

# CPU info
sysctl hw.model hw.ncpu

# Network interfaces
ifconfig -a
```

### Network Commands

```bash
# Routing table
netstat -rn

# Active connections
netstat -an

# Listening ports
sockstat -4 -l

# ARP table
arp -a

# DNS lookup
host google.com
nslookup google.com

# Ping
ping -c 3 8.8.8.8

# Traceroute
traceroute 8.8.8.8
```

### Process Management

```bash
# List processes
ps aux

# Find process
pgrep -l myapp
pgrep -f "myapp"

# Kill process
pkill myapp
kill $(cat /var/run/myapp.pid)

# Background process
nohup /usr/local/bin/myapp &
```

### File Operations

```bash
# Edit file
vi /path/to/file
ee /path/to/file    # Easy editor

# View file
cat /path/to/file
less /path/to/file

# Find files
find /usr/local -name "*.php"

# Grep in files
grep -r "pattern" /usr/local/www/
```

### Package Management

```bash
# List installed packages
pkg info

# Install package
pkg install packagename

# Remove package
pkg delete packagename

# Update packages
pkg update
pkg upgrade
```

---

## Common Pitfalls

### 1. Files Disappearing After Reboot

**Problem:** Files in `/var/`, `/tmp/` are gone after reboot.

**Solution:** Use persistent directories:
- `/usr/local/share/myapp/`
- `/usr/local/etc/myapp/`

### 2. Service Not Starting on Boot

**Problem:** Service doesn't start automatically.

**Checklist:**
1. RC script in `/usr/local/etc/rc.d/`
2. Script is executable (`chmod +x`)
3. `myapp_enable="YES"` in `/etc/rc.conf` or `/etc/rc.conf.local`
4. Check boot logs: `grep myapp /var/log/system.log`

### 3. Config Changes Not Applied

**Problem:** Modified `$config` but changes don't take effect.

**Solution:**
```php
write_config("Description");  // Save changes
filter_configure_sync();      // Apply firewall
interfaces_configure();       // Apply interfaces
```

### 4. PHP Script Fails Silently

**Problem:** PHP script doesn't work but no error.

**Solution:**
```php
// Enable error reporting
error_reporting(E_ALL);
ini_set('display_errors', 1);

// Or check error log
// /var/log/system.log
```

### 5. Network Breaks After Config Change

**Problem:** Can't access pfSense after applying changes.

**Solution:** Always call these after network changes:
```php
interface_configure($if, true, true);
system_routing_configure();
setup_gateways_monitor();
filter_configure_sync();
```

### 6. Permission Denied

**Problem:** Can't write to files or execute commands.

**Solution:**
- Run as root
- Check file permissions: `ls -la`
- Check directory permissions: `ls -la /path/to/directory/`

---

## Best Practices

### 1. Configuration

- Always use `write_config()` with a description
- Make backups before major changes
- Test changes on a non-production system first

### 2. File Storage

- Use `/usr/local/share/myapp/` for persistent data
- Use `/var/run/` only for PID files (will be lost on reboot)
- Never store important data in `/tmp/` or `/var/`

### 3. Logging

- Use syslog for logging (integrates with pfSense)
- Include app name in log messages
- Log important events and errors

### 4. Security

- Validate all user input
- Use CSRF protection for web forms
- Don't store passwords in plain text
- Use HTTPS for web interfaces

### 5. Service Management

- Create proper RC scripts
- Handle signals (SIGTERM, SIGHUP)
- Write PID files to `/var/run/`
- Clean up on shutdown

### 6. Error Handling

- Always check return values
- Log errors to syslog
- Provide meaningful error messages
- Don't fail silently

### 7. Updates & Compatibility

- Test with pfSense upgrades
- Don't modify core pfSense files
- Use hooks instead of patches
- Document dependencies

---

## Quick Reference Card

```
PERSISTENT DIRECTORIES:
  /usr/local/bin/          - Binaries
  /usr/local/etc/rc.d/     - RC scripts
  /usr/local/share/        - App data
  /cf/conf/                - Config files

NON-PERSISTENT (RAM):
  /tmp/                    - Temp files
  /var/                    - Variable data

SERVICE COMMANDS:
  service myapp start|stop|restart|status

KEY PHP INCLUDES:
  require_once("config.inc");
  require_once("interfaces.inc");
  require_once("filter.inc");

RELOAD SEQUENCE:
  write_config("msg");
  interface_configure($if, true, true);
  system_routing_configure();
  setup_gateways_monitor();
  filter_configure_sync();

VIEW LOGS:
  clog /var/log/system.log | grep myapp
```

---

*pfSense Development Guide - Last Updated: January 2026*
