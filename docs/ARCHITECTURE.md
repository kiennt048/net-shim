# Net-Shim Architecture Document

**Technical Design & Code Structure**

Version: 1.7.x | Last Updated: January 2026

---

## Table of Contents

1. [System Overview](#system-overview)
2. [Technology Stack](#technology-stack)
3. [Directory Structure](#directory-structure)
4. [Component Architecture](#component-architecture)
5. [Data Flow](#data-flow)
6. [Security Architecture](#security-architecture)
7. [pfSense Integration](#pfsense-integration)
8. [Configuration Management](#configuration-management)
9. [Error Handling](#error-handling)
10. [Performance Considerations](#performance-considerations)

---

## System Overview

Net-Shim is a lightweight web application that provides a simplified management interface for pfSense firewalls. It runs as a standalone Go binary on the pfSense system and communicates with pfSense's PHP subsystem to apply configuration changes.

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         Web Browser                              │
│                    (HTTPS on port 8443)                         │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                      Net-Shim (Go Binary)                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ HTTP Server │  │  Templates  │  │   Embedded PHP Scripts  │ │
│  │   (8443)    │  │   (HTML)    │  │                         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                     pfSense PHP Runtime                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ config.inc  │  │interfaces.inc│ │     filter.inc          │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
                                │
                                ▼
┌─────────────────────────────────────────────────────────────────┐
│                    pfSense System                                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────────┐ │
│  │ config.xml  │  │    pf       │  │   Network Interfaces    │ │
│  │             │  │ (firewall)  │  │                         │ │
│  └─────────────┘  └─────────────┘  └─────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
```

---

## Technology Stack

### Backend

| Component | Technology | Purpose |
|-----------|------------|---------|
| Language | Go 1.21+ | Main application |
| HTTP Server | net/http (stdlib) | Web server |
| Templates | html/template | HTML rendering |
| TLS | crypto/tls | HTTPS support |
| PHP Scripts | Embedded (go:embed) | pfSense integration |

### Frontend

| Component | Technology | Purpose |
|-----------|------------|---------|
| HTML | Go Templates | Page structure |
| CSS | Inline/Embedded | Styling |
| JavaScript | Vanilla JS | Interactivity |

### pfSense Integration

| Component | Technology | Purpose |
|-----------|------------|---------|
| Configuration | PHP Scripts | Read/Write config |
| Execution | /usr/local/bin/php | PHP runtime |
| Config Storage | /cf/conf/config.xml | pfSense config |

---

## Directory Structure

```
net-shim/
├── main.go                     # Application entry point
├── main_test.go                # Main tests
├── go.mod                      # Go module definition
├── go.sum                      # Dependency checksums
├── Makefile                    # Build automation
├── install.sh                  # Installation script
├── .version                    # Version tracking
│
├── internal/                   # Internal packages
│   ├── auth/                   # Authentication
│   │   ├── auth.go            # Session management
│   │   └── auth_test.go       # Auth tests
│   │
│   ├── pfsense/               # pfSense integration
│   │   ├── client.go          # PHP execution client
│   │   ├── client_test.go     # Client tests
│   │   ├── scripts.go         # Script embeddings
│   │   └── scripts/           # PHP scripts
│   │       ├── read_state.php      # Read interface state
│   │       ├── apply_config.php    # Apply configuration
│   │       ├── enable_interface.php # Enable/disable
│   │       ├── gateway_status.php  # Gateway monitoring
│   │       ├── traffic_stats.php   # Traffic statistics
│   │       ├── backup.php          # Backup config
│   │       ├── restore.php         # Restore config
│   │       ├── reset.php           # Factory reset
│   │       ├── reboot.php          # System reboot
│   │       └── shutdown.php        # System shutdown
│   │
│   └── tls/                   # TLS certificate management
│       └── cert.go            # Self-signed cert generation
│
├── templates/                  # HTML templates
│   ├── layout.html            # Base layout
│   ├── login.html             # Login page
│   ├── index.html             # Dashboard
│   ├── monitor.html           # Monitoring page
│   └── backup.html            # Backup & restore page
│
├── defaults/                   # Default configurations
│   └── config.xml             # Factory default config
│
└── docs/                       # Documentation
    ├── USER_GUIDE.md
    ├── ARCHITECTURE.md
    ├── INSTALL.md
    ├── API_REFERENCE.md
    ├── TROUBLESHOOTING.md
    └── CHANGELOG.md
```

---

## Component Architecture

### 1. Main Application (main.go)

**Responsibilities:**
- HTTP server initialization
- Route registration
- Template management
- CSRF token management
- Request validation

**Key Functions:**

```go
// Template rendering with layout
func render(w http.ResponseWriter, pageName string, data PageData)

// CSRF protection
func generateCSRFToken() string
func validateCSRFToken(token string) bool

// Input validation
func validateConfigRequest(req *ConfigRequest) error
```

### 2. Authentication Module (internal/auth/)

**Responsibilities:**
- Session management
- Login/logout handling
- Request authentication middleware

**Key Types:**

```go
type Session struct {
    Username  string
    CreatedAt time.Time
    ExpiresAt time.Time
}
```

**Key Functions:**

```go
func LoginHandler(w http.ResponseWriter, r *http.Request)
func LogoutHandler(w http.ResponseWriter, r *http.Request)
func RequireLogin(handler http.HandlerFunc) http.HandlerFunc
func CheckSession(sessionID string) bool
func GetUsername(sessionID string) string
```

### 3. pfSense Client (internal/pfsense/)

**Responsibilities:**
- Execute PHP scripts on pfSense
- Parse script output
- Handle errors from PHP execution

**Key Types:**

```go
type InterfaceStatus struct {
    Name        string `json:"name"`
    Status      string `json:"status"`
    IPAddr      string `json:"ipaddr"`
    Subnet      string `json:"subnet"`
    Gateway     string `json:"gateway"`
    PhysicalIF  string `json:"if"`
    MAC         string `json:"mac"`
    RXBytes     int64  `json:"rx_bytes"`
    TXBytes     int64  `json:"tx_bytes"`
    // ... more fields
}

type ConfigRequest struct {
    Interface       string `json:"interface"`
    Mode            string `json:"mode"`
    IpAddr          string `json:"ipaddr"`
    Subnet          string `json:"subnet"`
    Gateway         string `json:"gateway"`
    PPPoEUsername   string `json:"pppoe_username"`
    PPPoEPassword   string `json:"pppoe_password"`
    // ... more fields
}
```

**Key Functions:**

```go
func GetState() (map[string]InterfaceStatus, error)
func ApplyConfig(req ConfigRequest) error
func EnableInterface(name string, enabled bool) error
func BackupConfig() ([]byte, error)
func RestoreConfig(data []byte) (string, error)
func ResetConfig(defaultConfig []byte) (string, error)
func RebootSystem() error
func ShutdownSystem() error
func GetGatewayStatus() ([]GatewayInfo, error)
func GetWANTraffic() (*TrafficStats, error)
```

### 4. TLS Module (internal/tls/)

**Responsibilities:**
- Generate self-signed certificates
- Manage certificate storage

**Key Functions:**

```go
func EnsureCert() (certPath, keyPath string, err error)
```

---

## Data Flow

### 1. Interface Configuration Flow

```
User Input → HTTP POST /apply
    │
    ▼
Validate CSRF Token
    │
    ▼
Parse Form Data → ConfigRequest struct
    │
    ▼
Validate Input (regex, ranges, required fields)
    │
    ▼
Execute apply_config.php via pfsense.ApplyConfig()
    │
    ▼
PHP Script:
    ├── Modify $config array
    ├── Set NAT mode to automatic
    ├── write_config()
    ├── interface_configure()
    ├── system_routing_configure()
    ├── setup_gateways_monitor()
    ├── system_resolvconf_generate()
    └── filter_configure_sync()
    │
    ▼
Return success/error
    │
    ▼
Redirect to Dashboard with message
```

### 2. State Reading Flow

```
Dashboard Load / Stats API
    │
    ▼
Check Stats Cache (5-second TTL)
    │
    ├── Cache Hit → Return cached data
    │
    └── Cache Miss:
            │
            ▼
        Execute read_state.php
            │
            ▼
        PHP Script:
            ├── Read $config['interfaces']
            ├── get_interface_info()
            ├── get_interface_stats()
            └── Return JSON
            │
            ▼
        Parse JSON → map[string]InterfaceStatus
            │
            ▼
        Update cache
            │
            ▼
        Return to client
```

### 3. Authentication Flow

```
Login Request → POST /login
    │
    ▼
Extract username/password
    │
    ▼
Verify against pfSense local database
(via PHP script or direct config check)
    │
    ├── Invalid → Redirect to /login?error=invalid_credentials
    │
    └── Valid:
            │
            ▼
        Generate session ID (32 bytes, hex encoded)
            │
            ▼
        Store session in memory map
            │
            ▼
        Set cookie: netshim_sess
            │
            ▼
        Redirect to Dashboard
```

---

## Security Architecture

### 1. Authentication

| Feature | Implementation |
|---------|----------------|
| Session Storage | In-memory map with mutex |
| Session ID | 32 random bytes, hex encoded |
| Session Lifetime | 24 hours |
| Cookie Flags | HttpOnly, Secure (HTTPS) |

### 2. CSRF Protection

| Feature | Implementation |
|---------|----------------|
| Token Generation | 32 random bytes, hex encoded |
| Token Storage | In-memory map with timestamp |
| Token Lifetime | 1 hour |
| Token Usage | Single-use (deleted after validation) |
| Cleanup | Background goroutine every 30 minutes |

### 3. Input Validation

```go
var (
    ifaceNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)
    ipv4Regex      = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
    safeTextRegex  = regexp.MustCompile(`^[a-zA-Z0-9\s\-_.]{0,255}$`)
)
```

| Field | Validation |
|-------|------------|
| Interface Name | Lowercase alphanumeric, 1-16 chars |
| IP Address | IPv4 format + net.ParseIP() |
| Subnet | Integer 0-32 |
| Gateway | IPv4 format + net.ParseIP() |
| MTU | Integer 576-9000 |
| MSS | Integer 536-8960 |
| VLAN ID | Integer 1-4094 |
| Description | Alphanumeric + spaces, max 255 chars |

### 4. Output Sanitization

```go
func sanitizeMessage(msg string) string {
    msg = html.EscapeString(msg)  // Prevent XSS
    if len(msg) > 200 {
        msg = msg[:200] + "..."   // Limit length
    }
    return msg
}
```

### 5. TLS/HTTPS

| Feature | Implementation |
|---------|----------------|
| Certificate | Self-signed, auto-generated |
| Key Size | 2048-bit RSA |
| Validity | 10 year |
| Storage | /usr/local/share/netshim/ |
| HTTP Redirect | Port 8080 → 8443 |

---

## pfSense Integration

### PHP Script Execution

All pfSense operations are performed via PHP scripts that use pfSense's built-in libraries.

**Execution Method:**

```go
func executeScript(script string, env map[string]string) (string, error) {
    cmd := exec.Command("/usr/local/bin/php", "-q")
    cmd.Stdin = strings.NewReader(script)
    cmd.Env = append(os.Environ(), formatEnv(env)...)
    output, err := cmd.CombinedOutput()
    return string(output), err
}
```

### Required pfSense Includes

```php
require_once("config.inc");      // Configuration management
require_once("interfaces.inc");  // Interface functions
require_once("filter.inc");      // Firewall/NAT functions
require_once("util.inc");        // Utility functions
```

### Critical pfSense Functions

| Function | Purpose |
|----------|---------|
| `write_config()` | Save config.xml changes |
| `interface_configure()` | Apply interface settings |
| `interfaces_configure()` | Apply all interfaces |
| `system_routing_configure()` | Update routing table |
| `setup_gateways_monitor()` | Restart dpinger |
| `system_resolvconf_generate()` | Update DNS |
| `filter_configure_sync()` | Apply firewall + NAT rules |

### Configuration Reload Sequence

After any configuration change, the following sequence ensures proper system state:

```php
// 1. Save configuration
write_config("Description of change");

// 2. Apply interface changes
interface_configure($interface, true, true);

// 3. Update routing
system_routing_configure();

// 4. Restart gateway monitoring
setup_gateways_monitor();

// 5. Update DNS
system_resolvconf_generate();

// 6. Apply firewall and NAT rules (CRITICAL)
filter_configure_sync();
```

---

## Configuration Management

### Automatic Outbound NAT

Net-Shim automatically ensures outbound NAT is configured:

```php
// Set outbound NAT mode to automatic
$config['nat']['outbound']['mode'] = 'automatic';
```

This ensures all internal networks are automatically NAT'd through the WAN interface.

### Interface Mode Transitions

| From | To | Actions |
|------|-----|---------|
| Static | DHCP | Remove IP/subnet/gateway, set ipaddr='dhcp' |
| Static | PPPoE | Create PPP entry, set ipaddr='pppoe' |
| DHCP | Static | Set IP/subnet/gateway |
| DHCP | PPPoE | Create PPP entry, set ipaddr='pppoe' |
| PPPoE | Static | Remove PPP entry, restore physical interface |
| PPPoE | DHCP | Remove PPP entry, restore physical interface |

### PPPoE VLAN Handling

When PPPoE requires VLAN tagging:

1. Create VLAN entry in `$config['vlans']['vlan']`
2. Configure VLAN interface with `interfaces_vlan_configure()`
3. Set PPP ports to VLAN interface (e.g., `em0.35`)

---

## Error Handling

### Error Response Format

PHP scripts return errors in format: `ERROR:CODE`

| Code | Meaning |
|------|---------|
| `NO_PAYLOAD` | Missing request data |
| `INVALID_JSON` | JSON parse error |
| `MISSING_INTERFACE` | Interface name not provided |
| `MISSING_MODE` | Mode not specified |
| `IF_NOT_FOUND` | Interface doesn't exist |
| `INVALID_MODE` | Unknown mode value |
| `PPPOE_USERNAME_REQUIRED` | PPPoE missing username |
| `PPPOE_PASSWORD_REQUIRED` | PPPoE missing password |
| `VLAN_ID_REQUIRED` | VLAN enabled but no ID |
| `INVALID_VLAN_ID` | VLAN ID out of range |
| `INVALID_MTU` | MTU out of range |
| `INVALID_MSS` | MSS out of range |

### Go-side Error Handling

```go
output, err := executeScript(script, env)
if err != nil {
    return fmt.Errorf("script execution failed: %w", err)
}
if strings.HasPrefix(output, "ERROR:") {
    return fmt.Errorf("pfSense error: %s", output)
}
```

---

## Performance Considerations

### Stats Caching

```go
var (
    statsCache      *StatsResponse
    statsCacheMutex sync.RWMutex
    statsCacheTime  time.Time
)

// 5-second TTL for stats cache
if time.Since(statsCacheTime) < 5*time.Second {
    return statsCache
}
```

### Concurrent Access

- Session map: Protected by `sync.RWMutex`
- CSRF tokens: Protected by `sync.RWMutex`
- Stats cache: Protected by `sync.RWMutex`

### Resource Usage

| Resource | Typical Usage |
|----------|---------------|
| Memory | 10-20 MB |
| CPU | < 1% idle, spikes during config |
| Disk | Binary only, no runtime disk I/O |
| Network | Minimal (localhost PHP calls) |

---

## Build System

### Makefile Targets

| Target | Description |
|--------|-------------|
| `make build` | Build for pfSense (FreeBSD/amd64) |
| `make version` | Show current version |
| `make set-version VERSION=X.Y.Z` | Set new version |
| `make clean` | Remove build artifacts |
| `make test` | Run tests |

### Version Format

```
v{BASE_VERSION}.{BUILD_NUM}_{BUILD_TIME}
Example: v1.7.1.11_20260129_0936
```

### Cross-Compilation

```makefile
GOOS=freebsd
GOARCH=amd64
CGO_ENABLED=0
```

---

## Testing Strategy

### Unit Tests

- `main_test.go` - HTTP handler tests
- `internal/auth/auth_test.go` - Authentication tests
- `internal/pfsense/client_test.go` - Client tests

### Integration Tests

Require a running pfSense instance:
1. Deploy binary to test pfSense
2. Run smoke test script
3. Verify connectivity after operations

### Manual Testing

See `TEST_CHECKLIST.md` for comprehensive manual test procedures.

---

*Architecture Document - Net-Shim v1.7.x*
