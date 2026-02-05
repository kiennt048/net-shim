# Net-Shim Changelog

**Version History & Release Notes**

---

## Version Format

```
v{MAJOR}.{MINOR}.{PATCH}.{BUILD}_{BUILDTIME}
```

- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)
- **BUILD**: Auto-incremented build number
- **BUILDTIME**: Build timestamp (YYYYMMDD_HHMM)

---

## [1.7.1] - 2026-01-29

### Fixed - Critical Network Connectivity Issue

This release fixes a critical issue where network connectivity (NAT, routing, firewall rules) would break after applying configuration changes through Net-Shim.

#### Root Cause
The PHP scripts were not calling the complete set of pfSense reload functions after configuration changes, causing:
- NAT rules not applied
- Routing table incomplete
- Gateway monitoring not restarted
- Filter rules not synchronized

#### Changes

**apply_config.php:**
- Added `require_once("filter.inc")` for filter functions
- Added `setup_gateways_monitor()` to restart dpinger
- Added `system_resolvconf_generate()` to update DNS
- Changed `filter_configure()` to `filter_configure_sync()` for complete reload
- Added automatic outbound NAT configuration (`mode = automatic`)

**restore.php:**
- Added `system_routing_configure()` for routing
- Added `setup_gateways_monitor()` for gateway monitoring
- Added `system_resolvconf_generate()` for DNS
- Changed to `filter_configure_sync()`
- Added automatic outbound NAT configuration

**reset.php:**
- Added `system_routing_configure()` for routing
- Added `setup_gateways_monitor()` for gateway monitoring
- Added `system_resolvconf_generate()` for DNS
- Changed to `filter_configure_sync()`
- Added automatic outbound NAT configuration

**enable_interface.php:**
- Added `require_once("filter.inc")`
- Added `system_routing_configure()` after interface toggle
- Added `setup_gateways_monitor()` after interface toggle
- Added `filter_configure_sync()` after interface toggle
- Added automatic outbound NAT configuration

### Configuration Reload Sequence

After any configuration change, the following sequence is now executed:

```php
write_config();                    // Save configuration
interface_configure();             // Apply interface settings
system_routing_configure();        // Update routing table
setup_gateways_monitor();          // Restart gateway monitoring (dpinger)
system_resolvconf_generate();      // Update DNS configuration
filter_configure_sync();           // Apply firewall + NAT rules (complete)
```

### Automatic Outbound NAT

All configuration operations now automatically ensure outbound NAT is set to automatic mode:

```php
$config['nat']['outbound']['mode'] = 'automatic';
```

This ensures all internal networks are properly NAT'd through the WAN interface.

---

## [1.7.0] - 2026-01-15

### Added
- Monitor page with real-time gateway status
- Traffic statistics API (`/api/monitor/traffic`)
- Gateway status API (`/api/monitor/gateways`)
- System shutdown functionality
- Version endpoint (`/version`)

### Changed
- Improved dashboard UI with interface cards
- Better error messages for configuration failures
- Enhanced PPPoE configuration with VLAN support

### Fixed
- VLAN creation for PPPoE connections
- MTU/MSS validation ranges
- Session cleanup on logout

---

## [1.6.0] - 2026-01-01

### Added
- DHCP server configuration on LAN interfaces
- Custom DNS server options for DHCP
- Lease time configuration
- Pool range auto-calculation

### Changed
- Switched to KEA DHCP server (pfSense 2.8+)
- Improved form validation

### Fixed
- DHCP pool validation
- Interface description handling

---

## [1.5.0] - 2025-12-15

### Added
- Backup & Restore page
- Download configuration backup
- Upload and restore configuration
- Factory reset to defaults
- System reboot button

### Changed
- Improved navigation menu
- Added confirmation dialogs for dangerous operations

### Security
- Added file type validation for uploads
- Limited upload size to 5MB
- Added XML structure validation

---

## [1.4.0] - 2025-12-01

### Added
- PPPoE connection support
- VLAN tagging for PPPoE
- MTU and MSS configuration options

### Changed
- Interface mode switching improved
- Physical interface restoration when leaving PPPoE

### Fixed
- PPP entry cleanup when switching modes
- VLAN interface creation

---

## [1.3.0] - 2025-11-15

### Added
- Interface enable/disable toggle
- Unassigned NIC detection and assignment
- OPT interface auto-creation

### Changed
- Dashboard shows all physical NICs
- Improved status indicators

---

## [1.2.0] - 2025-11-01

### Added
- HTTPS support with self-signed certificates
- HTTP to HTTPS redirect
- TLS certificate auto-generation

### Security
- All traffic encrypted by default
- Secure cookie flags enabled

---

## [1.1.0] - 2025-10-15

### Added
- CSRF protection for all forms
- Input validation with regex patterns
- Output sanitization to prevent XSS
- Session timeout (24 hours)

### Security
- Single-use CSRF tokens
- Token expiration (1 hour)
- Automatic cleanup of expired tokens

---

## [1.0.0] - 2025-10-01

### Initial Release

#### Features
- Web-based dashboard for pfSense
- Interface configuration (Static, DHCP)
- Real-time interface status
- Authentication via pfSense credentials
- Responsive HTML templates

#### Supported Operations
- View interface status
- Configure static IP
- Configure DHCP client
- Set gateway
- View traffic statistics

#### Technical
- Single Go binary
- Embedded HTML templates
- Embedded PHP scripts
- Cross-compiled for FreeBSD/amd64

---

## Upgrade Notes

### From 1.6.x to 1.7.x

1. **Backup current binary:**
   ```bash
   cp /usr/local/bin/net-shim /usr/local/bin/net-shim.1.6.bak
   ```

2. **Deploy new binary:**
   ```bash
   scp net-shim root@pfSense:/usr/local/bin/
   chmod +x /usr/local/bin/net-shim
   ```

3. **Restart service:**
   ```bash
   service netshim restart
   ```

4. **Verify:**
   ```bash
   curl -sk https://127.0.0.1:8443/version
   ```

### From 1.5.x to 1.6.x

No special steps required. Standard upgrade procedure.

### From 1.4.x to 1.5.x

No special steps required. Standard upgrade procedure.

---

## Known Issues

### Current (1.7.x)

- None known

### Resolved in 1.7.x

- **Network connectivity breaks after config change** - FIXED
  - NAT rules not applied after interface configuration
  - Routing table incomplete after changes
  - Gateway monitoring not restarted

---

## Compatibility Matrix

| Net-Shim | pfSense | FreeBSD | Status |
|----------|---------|---------|--------|
| 1.7.x | 2.8.x | 16.x | ✅ Supported |
| 1.7.x | 2.7.x | 14.x | ✅ Supported |
| 1.6.x | 2.8.x | 16.x | ⚠️ Upgrade recommended |
| 1.6.x | 2.7.x | 14.x | ⚠️ Upgrade recommended |
| 1.5.x | 2.7.x | 14.x | ❌ Not supported |

---

## Contributing

### Reporting Issues

When reporting issues, please include:

1. Net-Shim version (`curl -sk https://localhost:8443/version`)
2. pfSense version (`cat /etc/version`)
3. Steps to reproduce
4. Expected vs actual behavior
5. Relevant log entries (`grep NetShim /var/log/system.log`)

### Feature Requests

Feature requests are welcome. Please describe:

1. Use case / problem to solve
2. Proposed solution
3. Any alternatives considered

---

*Changelog - Net-Shim*
