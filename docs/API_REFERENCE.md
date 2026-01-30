# Net-Shim API Reference

**REST API Documentation**

Version: 1.7.x

---

## Table of Contents

1. [Overview](#overview)
2. [Authentication](#authentication)
3. [Common Response Formats](#common-response-formats)
4. [Endpoints](#endpoints)
   - [Health & System](#health--system)
   - [Authentication](#authentication-endpoints)
   - [Dashboard & Stats](#dashboard--stats)
   - [Interface Configuration](#interface-configuration)
   - [Monitoring](#monitoring)
   - [Backup & Restore](#backup--restore)
   - [System Operations](#system-operations)

---

## Overview

### Base URL

```
https://<PFSENSE_IP>:8443
```

### Content Types

| Request | Content-Type |
|---------|--------------|
| Form submissions | `application/x-www-form-urlencoded` |
| File uploads | `multipart/form-data` |
| API responses | `application/json` |

### Authentication

All endpoints except `/health`, `/version`, and `/login` require authentication via session cookie.

---

## Authentication

### Session Cookie

After successful login, a session cookie is set:

```
Cookie: netshim_sess=<64-character-hex-string>
```

### CSRF Token

State-changing operations require a CSRF token in the request body:

```
csrf_token=<64-character-hex-string>
```

CSRF tokens are:
- Single-use (invalidated after use)
- Valid for 1 hour
- Included in HTML forms automatically

---

## Common Response Formats

### Success Response (JSON)

```json
{
  "status": "success",
  "data": { ... }
}
```

### Error Response (JSON)

```json
{
  "error": "Error message description"
}
```

### Redirect Response

Most form submissions redirect with a query parameter:

```
/?msg=success
/?msg=error:Description
```

---

## Endpoints

---

## Health & System

### GET /health

Health check endpoint. No authentication required.

**Request:**
```http
GET /health HTTP/1.1
Host: pfSense:8443
```

**Response:**
```
HTTP/1.1 200 OK
Content-Type: text/plain

OK
```

**Use Case:** Load balancer health checks, monitoring systems.

---

### GET /version

Version information. No authentication required.

**Request:**
```http
GET /version HTTP/1.1
Host: pfSense:8443
```

**Response:**
```json
{
  "version": "v1.7.1.11_20260129_0936",
  "base": "1.7.1",
  "build": "11",
  "build_time": "20260129_0936"
}
```

---

## Authentication Endpoints

### GET /login

Display login page.

**Request:**
```http
GET /login HTTP/1.1
Host: pfSense:8443
```

**Response:** HTML login form

**Query Parameters:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| error | `invalid_credentials` | Show error message |

---

### POST /login

Authenticate user.

**Request:**
```http
POST /login HTTP/1.1
Host: pfSense:8443
Content-Type: application/x-www-form-urlencoded

username=admin&password=pfsense
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| username | string | Yes | pfSense username |
| password | string | Yes | pfSense password |

**Success Response:**
```http
HTTP/1.1 303 See Other
Location: /
Set-Cookie: netshim_sess=abc123...; HttpOnly; Secure
```

**Error Response:**
```http
HTTP/1.1 303 See Other
Location: /login?error=invalid_credentials
```

---

### GET /logout

End user session.

**Request:**
```http
GET /logout HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
```

**Response:**
```http
HTTP/1.1 303 See Other
Location: /login
Set-Cookie: netshim_sess=; Max-Age=0
```

---

## Dashboard & Stats

### GET /

Main dashboard page.

**Request:**
```http
GET / HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
```

**Response:** HTML dashboard page

**Query Parameters:**

| Parameter | Value | Description |
|-----------|-------|-------------|
| msg | `success` | Show success message |
| msg | `error:text` | Show error message |

---

### GET /stats

Interface statistics API (JSON).

**Request:**
```http
GET /stats HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
```

**Response:**
```json
{
  "interfaces": {
    "wan": {
      "name": "WAN",
      "status": "up",
      "ipaddr": "192.168.1.100",
      "subnet": "24",
      "gateway": "192.168.1.1",
      "if": "em0",
      "mac": "00:11:22:33:44:55",
      "rx_bytes": 1234567890,
      "tx_bytes": 987654321,
      "rx_packets": 12345,
      "tx_packets": 9876,
      "errors": 0,
      "collisions": 0
    },
    "lan": {
      "name": "LAN",
      "status": "up",
      "ipaddr": "10.0.0.1",
      "subnet": "24",
      "if": "em1",
      "mac": "00:11:22:33:44:56",
      "rx_bytes": 5678901234,
      "tx_bytes": 4321098765,
      "rx_packets": 56789,
      "tx_packets": 43210,
      "errors": 0,
      "collisions": 0
    }
  },
  "timestamp": 1706500000,
  "error": ""
}
```

**Response Fields:**

| Field | Type | Description |
|-------|------|-------------|
| interfaces | object | Map of interface name to status |
| timestamp | integer | Unix timestamp |
| error | string | Error message if any |

**Interface Object Fields:**

| Field | Type | Description |
|-------|------|-------------|
| name | string | Display name |
| status | string | "up" or "down" |
| ipaddr | string | IP address or mode ("dhcp", "pppoe") |
| subnet | string | Subnet mask (CIDR) |
| gateway | string | Gateway IP (WAN only) |
| if | string | Physical interface name |
| mac | string | MAC address |
| rx_bytes | integer | Received bytes |
| tx_bytes | integer | Transmitted bytes |
| rx_packets | integer | Received packets |
| tx_packets | integer | Transmitted packets |
| errors | integer | Error count |
| collisions | integer | Collision count |

**Caching:** Response is cached for 5 seconds.

---

## Interface Configuration

### POST /apply

Apply interface configuration.

**Request:**
```http
POST /apply HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
Content-Type: application/x-www-form-urlencoded

csrf_token=xyz789...&interface=wan&mode=dhcp
```

**Common Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| csrf_token | string | Yes | CSRF protection token |
| interface | string | Yes | Interface name (wan, lan, opt1, etc.) |
| mode | string | Yes | Configuration mode |
| description | string | No | Interface description |
| mtu | integer | No | MTU (576-9000) |
| mss | integer | No | MSS (536-8960) |

**Mode: static**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| ipaddr | string | Yes | IP address |
| subnet | integer | Yes | Subnet mask (0-32) |
| gateway | string | No | Gateway IP |
| dhcp_server_enable | string | No | "on" to enable DHCP server |
| dhcp_pool_start | string | No | DHCP pool start IP |
| dhcp_pool_end | string | No | DHCP pool end IP |
| dhcp_lease_time | integer | No | Lease time in seconds |
| dhcp_dns1 | string | No | Primary DNS |
| dhcp_dns2 | string | No | Secondary DNS |

**Mode: dhcp**

No additional parameters required.

**Mode: pppoe**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| pppoe_username | string | Yes | PPPoE username |
| pppoe_password | string | Yes* | PPPoE password (*required for new config) |
| pppoe_vlan_enable | string | No | "on" to enable VLAN |
| pppoe_vlan_id | integer | Cond. | VLAN ID (1-4094), required if VLAN enabled |
| pppoe_vlan_desc | string | No | VLAN description |

**Success Response:**
```http
HTTP/1.1 303 See Other
Location: /?msg=success
```

**Error Response:**
```http
HTTP/1.1 303 See Other
Location: /?msg=error:Configuration+failed
```

**Example - Static IP:**
```bash
curl -k -X POST https://pfSense:8443/apply \
  -b "netshim_sess=abc123..." \
  -d "csrf_token=xyz789..." \
  -d "interface=lan" \
  -d "mode=static" \
  -d "ipaddr=10.0.0.1" \
  -d "subnet=24"
```

**Example - DHCP Client:**
```bash
curl -k -X POST https://pfSense:8443/apply \
  -b "netshim_sess=abc123..." \
  -d "csrf_token=xyz789..." \
  -d "interface=wan" \
  -d "mode=dhcp"
```

**Example - PPPoE with VLAN:**
```bash
curl -k -X POST https://pfSense:8443/apply \
  -b "netshim_sess=abc123..." \
  -d "csrf_token=xyz789..." \
  -d "interface=wan" \
  -d "mode=pppoe" \
  -d "pppoe_username=user@isp.com" \
  -d "pppoe_password=secret123" \
  -d "pppoe_vlan_enable=on" \
  -d "pppoe_vlan_id=35"
```

---

### POST /interface/toggle

Enable or disable an interface.

**Request:**
```http
POST /interface/toggle HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
Content-Type: application/x-www-form-urlencoded

csrf_token=xyz789...&interface=opt1&enabled=1
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| csrf_token | string | Yes | CSRF token |
| interface | string | Yes | Interface name |
| enabled | string | Yes | "1" to enable, "0" to disable |

**Success Response:**
```http
HTTP/1.1 303 See Other
Location: /?msg=success:Interface+OPT1+enabled+successfully
```

---

## Monitoring

### GET /monitor

Monitoring page.

**Request:**
```http
GET /monitor HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
```

**Response:** HTML monitoring page

---

### GET /api/monitor/gateways

Gateway status API.

**Request:**
```http
GET /api/monitor/gateways HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
```

**Response:**
```json
{
  "gateways": [
    {
      "name": "WAN_DHCP",
      "gateway": "192.168.1.1",
      "monitor": "192.168.1.1",
      "status": "online",
      "rtt": "1.5ms",
      "loss": "0%",
      "interface": "wan"
    }
  ]
}
```

**Gateway Object Fields:**

| Field | Type | Description |
|-------|------|-------------|
| name | string | Gateway name |
| gateway | string | Gateway IP |
| monitor | string | Monitor IP |
| status | string | "online", "offline", "pending" |
| rtt | string | Round-trip time |
| loss | string | Packet loss percentage |
| interface | string | Associated interface |

---

### GET /api/monitor/traffic

WAN traffic statistics.

**Request:**
```http
GET /api/monitor/traffic HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
```

**Response:**
```json
{
  "interface": "em0",
  "rx_bytes": 1234567890,
  "tx_bytes": 987654321,
  "rx_rate": "1.5 Mbps",
  "tx_rate": "0.8 Mbps"
}
```

---

## Backup & Restore

### GET /backup

Backup & restore page.

**Request:**
```http
GET /backup HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
```

**Response:** HTML backup page

---

### GET /backup/download

Download configuration backup.

**Request:**
```http
GET /backup/download HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
```

**Response:**
```http
HTTP/1.1 200 OK
Content-Type: application/xml
Content-Disposition: attachment; filename=config-2026-01-29-093600.xml

<?xml version="1.0"?>
<pfsense>
  ...
</pfsense>
```

---

### POST /backup/restore

Restore configuration from backup.

**Request:**
```http
POST /backup/restore HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary

------WebKitFormBoundary
Content-Disposition: form-data; name="csrf_token"

xyz789...
------WebKitFormBoundary
Content-Disposition: form-data; name="config_file"; filename="config.xml"
Content-Type: application/xml

<?xml version="1.0"?>
<pfsense>...</pfsense>
------WebKitFormBoundary--
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| csrf_token | string | Yes | CSRF token |
| config_file | file | Yes | XML configuration file (max 5MB) |

**Success Response:**
```http
HTTP/1.1 303 See Other
Location: /backup?msg=reboot:Configuration+restored+successfully
```

**Error Responses:**

| Error | Description |
|-------|-------------|
| `error:File too large` | File exceeds 5MB limit |
| `error:No file uploaded` | File missing from request |
| `error:Invalid file type` | Not an XML file |
| `error:Restore failed` | PHP script error |

---

### POST /backup/reset

Reset to factory defaults.

**Request:**
```http
POST /backup/reset HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
Content-Type: application/x-www-form-urlencoded

csrf_token=xyz789...
```

**Success Response:**
```http
HTTP/1.1 303 See Other
Location: /backup?msg=reboot:System+reset+to+factory+defaults
```

---

## System Operations

### POST /system/reboot

Reboot the system.

**Request:**
```http
POST /system/reboot HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
Content-Type: application/x-www-form-urlencoded

csrf_token=xyz789...
```

**Success Response:**
```http
HTTP/1.1 303 See Other
Location: /backup?msg=rebooting:System+is+rebooting
```

**Note:** System will be unavailable for 1-3 minutes.

---

### POST /system/shutdown

Shutdown the system.

**Request:**
```http
POST /system/shutdown HTTP/1.1
Host: pfSense:8443
Cookie: netshim_sess=abc123...
Content-Type: application/x-www-form-urlencoded

csrf_token=xyz789...
```

**Success Response:**
```http
HTTP/1.1 303 See Other
Location: /backup?msg=shutdown:System+is+shutting+down
```

**Note:** Manual intervention required to power on.

---

## Error Codes

### HTTP Status Codes

| Code | Description |
|------|-------------|
| 200 | Success |
| 303 | Redirect (after form submission) |
| 400 | Bad request |
| 401 | Unauthorized (not logged in) |
| 405 | Method not allowed |
| 500 | Internal server error |

### Application Error Codes

| Code | Description |
|------|-------------|
| `NO_PAYLOAD` | Missing request data |
| `INVALID_JSON` | JSON parse error |
| `MISSING_INTERFACE` | Interface name required |
| `MISSING_MODE` | Mode required |
| `IF_NOT_FOUND` | Interface not found |
| `INVALID_MODE` | Unknown mode |
| `PPPOE_USERNAME_REQUIRED` | PPPoE username required |
| `PPPOE_PASSWORD_REQUIRED` | PPPoE password required |
| `VLAN_ID_REQUIRED` | VLAN ID required |
| `INVALID_VLAN_ID` | VLAN ID out of range |
| `INVALID_MTU` | MTU out of range |
| `INVALID_MSS` | MSS out of range |
| `CANNOT_DISABLE_UNASSIGNED` | Cannot disable unassigned interface |

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| /stats | Cached 5 seconds |
| /login | No rate limit (use fail2ban) |
| /apply | No rate limit |

---

## Example: Full Configuration Script

```bash
#!/bin/bash
# Example: Configure WAN as DHCP and LAN as static with DHCP server

PFSENSE="192.168.1.1"
USERNAME="admin"
PASSWORD="pfsense"

# 1. Login and get session cookie
COOKIE=$(curl -k -s -c - -X POST "https://$PFSENSE:8443/login" \
  -d "username=$USERNAME&password=$PASSWORD" \
  | grep netshim_sess | awk '{print $7}')

echo "Session: $COOKIE"

# 2. Get CSRF token (from dashboard HTML)
CSRF=$(curl -k -s -b "netshim_sess=$COOKIE" "https://$PFSENSE:8443/" \
  | grep -o 'name="csrf_token" value="[^"]*"' | head -1 \
  | sed 's/.*value="\([^"]*\)".*/\1/')

echo "CSRF: $CSRF"

# 3. Configure WAN as DHCP
curl -k -X POST "https://$PFSENSE:8443/apply" \
  -b "netshim_sess=$COOKIE" \
  -d "csrf_token=$CSRF" \
  -d "interface=wan" \
  -d "mode=dhcp"

# 4. Get new CSRF token
CSRF=$(curl -k -s -b "netshim_sess=$COOKIE" "https://$PFSENSE:8443/" \
  | grep -o 'name="csrf_token" value="[^"]*"' | head -1 \
  | sed 's/.*value="\([^"]*\)".*/\1/')

# 5. Configure LAN as static with DHCP server
curl -k -X POST "https://$PFSENSE:8443/apply" \
  -b "netshim_sess=$COOKIE" \
  -d "csrf_token=$CSRF" \
  -d "interface=lan" \
  -d "mode=static" \
  -d "ipaddr=10.0.0.1" \
  -d "subnet=24" \
  -d "dhcp_server_enable=on" \
  -d "dhcp_pool_start=10.0.0.100" \
  -d "dhcp_pool_end=10.0.0.200" \
  -d "dhcp_dns1=8.8.8.8" \
  -d "dhcp_dns2=1.1.1.1"

echo "Configuration complete!"
```

---

*API Reference - Net-Shim v1.7.x*
