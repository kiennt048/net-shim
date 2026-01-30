# Net-Shim User Guide

**BEYONDNET Firewall Control Panel**

Version: 1.7.x | pfSense 2.8.x Compatible

---

## Table of Contents

1. [Introduction](#introduction)
2. [Getting Started](#getting-started)
3. [Dashboard Overview](#dashboard-overview)
4. [Interface Configuration](#interface-configuration)
5. [Monitoring](#monitoring)
6. [Backup & Restore](#backup--restore)
7. [System Operations](#system-operations)
8. [Best Practices](#best-practices)

---

## Introduction

Net-Shim is a simplified web-based control panel for pfSense firewalls. It provides an easy-to-use interface for common network configuration tasks without the complexity of the full pfSense WebGUI.

### Key Features

- **Interface Configuration** - Configure WAN, LAN, and optional interfaces
- **Multiple Connection Types** - Static IP, DHCP, and PPPoE support
- **DHCP Server** - Built-in DHCP server configuration
- **Real-time Monitoring** - Gateway status and traffic statistics
- **Backup & Restore** - Configuration backup and restore functionality
- **Secure Access** - HTTPS with authentication and CSRF protection

### System Requirements

- pfSense 2.8.x or later
- FreeBSD 16.x base system
- Minimum 512MB RAM
- Web browser with JavaScript enabled

---

## Getting Started

### Accessing the Control Panel

1. Open your web browser
2. Navigate to: `https://<pfSense-IP>:8443`
3. Accept the self-signed certificate warning (first time only)
4. Enter your credentials at the login screen

### Default Access

| Setting | Value |
|---------|-------|
| Primary URL | `http://<IP>:8080` |
| HTTPS URL | `https://<IP>:8443` (if TLS enabled) |
| Username | Your pfSense admin username |
| Password | Your pfSense admin password |

> **Note:** HTTPS is available on port 8443 only if TLS certificate generation succeeds. If TLS fails, the app runs on HTTP port 8080 only.

### First Login

1. Enter your pfSense administrator credentials
2. Click **Login**
3. You will be redirected to the Dashboard

---

## Dashboard Overview

The Dashboard is your main control center showing all network interfaces.

### Interface Cards

Each interface is displayed as a card showing:

| Element | Description |
|---------|-------------|
| **Name** | Interface name (WAN, LAN, OPT1, etc.) |
| **Status Indicator** | Green = Up, Red = Down |
| **IP Address** | Current IP address or "DHCP"/"PPPoE" |
| **Subnet** | Network mask in CIDR notation |
| **Gateway** | Gateway IP (for WAN interfaces) |
| **Physical Port** | Hardware interface (em0, igb0, etc.) |
| **MAC Address** | Hardware MAC address |
| **Traffic Stats** | RX/TX bytes and packets |

### Quick Actions

| Button | Action |
|--------|--------|
| **Configure** | Open interface configuration dialog |
| **Enable/Disable** | Toggle interface on/off |

---

## Interface Configuration

### Opening Configuration

1. Click the **Configure** button on any interface card
2. The configuration dialog will appear

### Connection Modes

#### Static IP

Use when you have a fixed IP address from your ISP or for internal networks.

| Field | Description | Example |
|-------|-------------|---------|
| IP Address | The static IP to assign | `192.168.1.1` |
| Subnet Mask | Network prefix length | `24` (255.255.255.0) |
| Gateway | Upstream gateway (WAN only) | `192.168.1.254` |
| Description | Optional description | `Main WAN` |

**Steps:**
1. Select **Static** mode
2. Enter IP Address
3. Enter Subnet (1-32)
4. Enter Gateway (for WAN)
5. Click **Apply**

#### DHCP Client

Use when your ISP provides IP addresses automatically.

**Steps:**
1. Select **DHCP** mode
2. Optionally set MTU/MSS
3. Click **Apply**

The interface will automatically obtain:
- IP Address
- Subnet Mask
- Gateway
- DNS Servers

#### PPPoE

Use for DSL/Fiber connections requiring PPPoE authentication.

| Field | Description | Required |
|-------|-------------|----------|
| Username | PPPoE username from ISP | Yes |
| Password | PPPoE password | Yes (new) / No (update) |
| VLAN Enable | Enable VLAN tagging | No |
| VLAN ID | VLAN tag (1-4094) | If VLAN enabled |

**Steps:**
1. Select **PPPoE** mode
2. Enter Username
3. Enter Password
4. Enable VLAN if required by ISP
5. Enter VLAN ID (common: 35, 100)
6. Click **Apply**

### DHCP Server Configuration

Enable a DHCP server on LAN/OPT interfaces to automatically assign IPs to clients.

| Field | Description | Default |
|-------|-------------|---------|
| Enable DHCP | Turn on DHCP server | Off |
| Pool Start | First IP in range | Auto-calculated |
| Pool End | Last IP in range | Auto-calculated |
| Lease Time | Lease duration (seconds) | 7200 |
| DNS Server 1 | Primary DNS | 8.8.8.8 |
| DNS Server 2 | Secondary DNS | 1.1.1.1 |

**Steps:**
1. Configure interface in **Static** mode first
2. Check **Enable DHCP Server**
3. Adjust pool range if needed
4. Set DNS servers
5. Click **Apply**

### Advanced Options

| Option | Description | Range |
|--------|-------------|-------|
| MTU | Maximum Transmission Unit | 576-9000 |
| MSS | Maximum Segment Size | 536-8960 |

**When to adjust:**
- PPPoE connections: MTU 1492, MSS 1452
- VPN tunnels: Reduce by 40-100 bytes
- Jumbo frames: MTU 9000 (requires switch support)

---

## Monitoring

Access the Monitor page from the navigation menu.

### Gateway Status

Shows real-time gateway health:

| Metric | Description |
|--------|-------------|
| **Name** | Gateway name |
| **Status** | Online/Offline/Pending |
| **RTT** | Round-trip time (latency) |
| **Loss** | Packet loss percentage |
| **Interface** | Associated interface |

### Traffic Statistics

Real-time traffic counters for each interface:

| Metric | Description |
|--------|-------------|
| **RX Bytes** | Total bytes received |
| **TX Bytes** | Total bytes transmitted |
| **RX Packets** | Total packets received |
| **TX Packets** | Total packets transmitted |
| **Errors** | Error count |

---

## Backup & Restore

Access from the navigation menu: **Backup & Restore**

### Download Backup

Creates a complete backup of your pfSense configuration.

1. Click **Download Backup**
2. Save the XML file to a secure location
3. File naming: `config-YYYY-MM-DD-HHMMSS.xml`

**Recommendation:** Create backups before making major changes.

### Restore Configuration

Restore a previously saved configuration.

1. Click **Choose File**
2. Select your backup XML file
3. Click **Restore**
4. **Reboot** when prompted (recommended)

**Warning:** Restoring will overwrite your current configuration.

### Factory Reset

Reset to default configuration.

1. Click **Reset to Defaults**
2. Confirm the action
3. **Reboot** when prompted

**Warning:** This will erase all custom settings.

### System Reboot

Restart the pfSense system.

1. Click **Reboot System**
2. Wait for system to come back online (1-3 minutes)

### System Shutdown

Power off the pfSense system.

1. Click **Shutdown System**
2. System will power off
3. Manual intervention required to power on

---

## System Operations

### Enable/Disable Interface

Toggle an interface without deleting its configuration.

1. Find the interface card on Dashboard
2. Click the **Enable** or **Disable** toggle
3. Configuration is preserved

### Assign Unassigned NIC

Physical NICs not yet assigned to an interface:

1. Unassigned NICs appear with "_unassigned_" prefix
2. Click **Enable** to assign
3. A new OPT interface is created automatically

---

## Best Practices

### Before Making Changes

1. **Create a backup** before major configuration changes
2. **Test from a different connection** if modifying WAN
3. **Have console access** ready in case of lockout

### Network Configuration

| Scenario | Recommendation |
|----------|----------------|
| Home Network | WAN: DHCP, LAN: Static + DHCP Server |
| Business | WAN: Static or PPPoE, Multiple VLANs |
| PPPoE Connection | Check ISP for VLAN requirements |

### Security

1. **Change default passwords** immediately
2. **Use HTTPS** (enabled by default on port 8443)
3. **Limit management access** to trusted networks
4. **Regular backups** stored securely off-device

### Troubleshooting Quick Tips

| Issue | Quick Fix |
|-------|-----------|
| Can't access internet | Check WAN status, verify gateway |
| DHCP not working | Ensure interface is in Static mode first |
| PPPoE won't connect | Verify credentials and VLAN settings |
| Lost access | Connect via console, check interface IPs |

---

## Keyboard Shortcuts

| Key | Action |
|-----|--------|
| `Esc` | Close dialog |
| `Enter` | Submit form (in dialogs) |

---

## Support

For issues and feature requests:
- GitHub: https://github.com/anthropics/claude-code/issues
- Documentation: See TROUBLESHOOTING.md

---

*BEYONDNET Firewall Control - Simplified pfSense Management*
