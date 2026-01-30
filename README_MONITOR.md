# BEYONDNET Monitor Feature - Integration Guide

## Overview

This update adds real-time monitoring capabilities to the BEYONDNET Firewall Control System:

1. **Gateway Status** - Real-time status of all IPv4 gateways (including PPPoE and VLAN gateways)
2. **WAN Traffic Graph** - Live bandwidth monitoring with historical chart (last hour)

## Files to Integrate

### 1. Replace `templates/monitor.html`
Copy `monitor.html` to your `templates/` directory, replacing the existing placeholder.

### 2. Add Monitor Functions to `internal/pfsense/client.go`
Add the following code from `client_monitor.go` to your `client.go`:
- `GatewayStatus` struct
- `TrafficData` struct  
- `GetGatewayStatus()` function
- `GetWANTraffic()` function

### 3. Add PHP Scripts to `internal/pfsense/scripts.go`
Add the following constants from `scripts_monitor.go` to your `scripts.go`:
- `PhpRESTAPIGatewayScript` - REST API method (primary)
- `PhpGatewayStatusScript` - PHP fallback method
- `PhpWANTrafficScript` - Traffic statistics

### 4. Add API Handlers to `main.go`
Add the following handlers from `monitor_api.go`:

```go
// Add these struct definitions near the top of main.go:
type GatewayResponse struct {
    Gateways  []pfsense.GatewayStatus `json:"gateways"`
    Error     string                   `json:"error,omitempty"`
    Timestamp int64                    `json:"timestamp"`
}

type TrafficResponse struct {
    Interface string `json:"interface"`
    BytesIn   uint64 `json:"bytes_in"`
    BytesOut  uint64 `json:"bytes_out"`
    Error     string `json:"error,omitempty"`
    Timestamp int64  `json:"timestamp"`
}

// Add these handlers in main():

// --- MONITOR API: Gateway Status ---
http.HandleFunc("/api/monitor/gateways", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    
    gateways, err := pfsense.GetGatewayStatus()
    if err != nil {
        log.Printf("⚠️ Gateway status fetch failed: %v", err)
        json.NewEncoder(w).Encode(GatewayResponse{
            Error:     err.Error(),
            Timestamp: time.Now().Unix(),
        })
        return
    }
    
    json.NewEncoder(w).Encode(GatewayResponse{
        Gateways:  gateways,
        Timestamp: time.Now().Unix(),
    })
}))

// --- MONITOR API: Traffic Data ---
http.HandleFunc("/api/monitor/traffic", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
    w.Header().Set("Content-Type", "application/json")
    
    traffic, err := pfsense.GetWANTraffic()
    if err != nil {
        log.Printf("⚠️ Traffic data fetch failed: %v", err)
        json.NewEncoder(w).Encode(TrafficResponse{
            Error:     err.Error(),
            Timestamp: time.Now().Unix(),
        })
        return
    }
    
    json.NewEncoder(w).Encode(TrafficResponse{
        Interface: traffic.Interface,
        BytesIn:   traffic.BytesIn,
        BytesOut:  traffic.BytesOut,
        Timestamp: traffic.Timestamp,
    })
}))
```

## pfSense REST API Setup (Recommended)

For best results, install the pfSense REST API package:

### Installation (pfSense CE 2.7.x / 2.8.x)
```bash
# SSH to pfSense and run:
pkg-static add https://github.com/jaredhendrickson13/pfsense-api/releases/latest/download/pfSense-2.8.1-pkg-RESTAPI.pkg

# Restart web GUI
/etc/rc.restart_webgui
```

### Installation (pfSense Plus 24.x / 25.x)
```bash
pkg-static -C /dev/null add https://github.com/jaredhendrickson13/pfsense-api/releases/latest/download/pfSense-25.11-pkg-RESTAPI.pkg
```

### Configuration
1. Navigate to **System → REST API** in pfSense web GUI
2. Enable the REST API
3. Configure authentication:
   - **Basic Auth** (default) - Uses pfSense user credentials
   - **API Key** - Generate keys under REST API → Keys

### Verify Installation
```bash
curl -k -u admin:password https://your-pfsense/api/v2/status/gateways
```

## Features

### Gateway Status
- Displays all IPv4 gateways (PPPoE, VLAN, static)
- Shows real-time status: Online, Offline, High Loss, High Delay
- Displays latency (ms) and packet loss (%)
- Updates every 5 seconds

### Traffic Graph
- Real-time inbound/outbound bandwidth
- Historical chart (last 10 minutes visible, 1 hour stored)
- Current speed in Mbps/Gbps
- Total data transferred in last hour
- Pauses when tab is hidden (resource optimization)

## API Endpoints

### GET /api/monitor/gateways
Returns current gateway status.

**Response:**
```json
{
  "gateways": [
    {
      "name": "WAN_DHCP",
      "interface": "WAN",
      "gateway": "192.168.1.1",
      "monitor": "8.8.8.8",
      "status": "online",
      "delay": "12.34 ms",
      "stddev": "2.10 ms",
      "loss": "0.0%"
    }
  ],
  "timestamp": 1706380800
}
```

### GET /api/monitor/traffic
Returns WAN interface traffic statistics.

**Response:**
```json
{
  "interface": "em0",
  "bytes_in": 1234567890,
  "bytes_out": 987654321,
  "timestamp": 1706380800
}
```

## Data Sources

The monitor uses multiple data sources in priority order:

### Gateway Status
1. **pfSense REST API** (`/api/v2/status/gateways`) - If installed
2. **Native pfSense functions** (`return_gateways_status()`)
3. **dpinger status files** (`/tmp/dpinger_*.status`)
4. **Direct ping test** - Last resort fallback

### Traffic Data
1. **pfSense_get_interface_stats()** - Native PHP function
2. **netstat -I** - Fallback for PPPoE interfaces

## Troubleshooting

### "REST API Not Connected"
- Verify REST API package is installed
- Check authentication settings
- Ensure firewall allows localhost connections

### No Gateway Data
- Check if gateways are configured in pfSense
- Verify dpinger service is running: `service dpinger status`
- Check `/tmp/dpinger_*.status` files exist

### No Traffic Data
- Verify WAN interface is configured
- Check interface name matches config
- For PPPoE: ensure PPP interface exists

## Browser Compatibility
- Chrome 80+
- Firefox 75+
- Safari 13+
- Edge 80+

## Security Notes
- All API endpoints require authentication
- Data is fetched server-side only
- No external API calls from browser
- CSRF protection on all forms
