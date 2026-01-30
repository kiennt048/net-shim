package pfsense

import (
	"testing"
)

// Test ConfigRequest data structure creation
func TestConfigRequest_Static(t *testing.T) {
	req := ConfigRequest{
		Interface: "wan",
		Mode:      "static",
		IpAddr:    "192.168.1.1",
		Subnet:    "24",
		Gateway:   "192.168.1.254",
	}

	if req.Interface != "wan" {
		t.Errorf("Expected interface 'wan', got '%s'", req.Interface)
	}
	if req.Mode != "static" {
		t.Errorf("Expected mode 'static', got '%s'", req.Mode)
	}
}

// Test ConfigRequest for DHCP mode
func TestConfigRequest_DHCP(t *testing.T) {
	req := ConfigRequest{
		Interface: "wan",
		Mode:      "dhcp",
	}

	if req.IpAddr != "" {
		t.Errorf("DHCP mode should have empty IpAddr, got '%s'", req.IpAddr)
	}
}

// Test ConfigRequest for PPPoE with VLAN
func TestConfigRequest_PPPoEWithVLAN(t *testing.T) {
	req := ConfigRequest{
		Interface:       "wan",
		Mode:            "pppoe",
		PPPoEUsername:   "user@isp.com",
		PPPoEPassword:   "secret123",
		PPPoEVlanEnable: true,
		PPPoEVlanID:     "100",
		PPPoEVlanDesc:   "ISP VLAN",
	}

	if !req.PPPoEVlanEnable {
		t.Error("VLAN should be enabled")
	}
	if req.PPPoEVlanID != "100" {
		t.Errorf("Expected VLAN ID '100', got '%s'", req.PPPoEVlanID)
	}
}

// Test ConfigRequest for DHCP Server configuration
func TestConfigRequest_DHCPServer(t *testing.T) {
	req := ConfigRequest{
		Interface:        "lan",
		Mode:             "static",
		IpAddr:           "192.168.1.1",
		Subnet:           "24",
		DHCPServerEnable: true,
		DHCPPoolStart:    "192.168.1.100",
		DHCPPoolEnd:      "192.168.1.200",
		DHCPLeaseTime:    "7200",
		DHCPDNS1:         "8.8.8.8",
		DHCPDNS2:         "1.1.1.1",
	}

	if !req.DHCPServerEnable {
		t.Error("DHCP server should be enabled")
	}
	if req.DHCPPoolStart != "192.168.1.100" {
		t.Errorf("Expected pool start '192.168.1.100', got '%s'", req.DHCPPoolStart)
	}
}

// Test InterfaceStatus data structure
func TestInterfaceStatus(t *testing.T) {
	status := InterfaceStatus{
		Name:        "wan",
		DisplayName: "WAN",
		Status:      "up",
		Mode:        "dhcp",
		IpAddr:      "192.168.1.100",
		Subnet:      "24",
		Enabled:     true,
	}

	if status.Name != "wan" {
		t.Errorf("Expected name 'wan', got '%s'", status.Name)
	}
	if !status.Enabled {
		t.Error("Interface should be enabled")
	}
}

// Test GatewayStatus data structure
func TestGatewayStatus(t *testing.T) {
	gw := GatewayStatus{
		Name:      "WAN_DHCP",
		Interface: "WAN",
		Gateway:   "192.168.1.1",
		Status:    "online",
		Delay:     "10.5 ms",
		Loss:      "0%",
	}

	if gw.Status != "online" {
		t.Errorf("Expected status 'online', got '%s'", gw.Status)
	}
}

// Test TrafficData data structure
func TestTrafficData(t *testing.T) {
	traffic := TrafficData{
		Interface: "pppoe0",
		BytesIn:   123456789,
		BytesOut:  987654321,
		Timestamp: 1706454000,
	}

	if traffic.BytesIn <= traffic.BytesOut {
		// Just a data structure test, no real assertion needed
	}

	if traffic.Interface != "pppoe0" {
		t.Errorf("Expected interface 'pppoe0', got '%s'", traffic.Interface)
	}
}
