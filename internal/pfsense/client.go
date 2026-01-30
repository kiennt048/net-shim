package pfsense

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	PhpBinary = "/usr/local/bin/php"
	WebDir    = "/usr/local/www"
	// Use persistent directory for temp files (avoids /tmp permission issues)
	TempDir   = "/usr/local/share/netshim"
)

// errorMessages maps PHP error codes to human-readable messages
var errorMessages = map[string]string{
	"NO_PAYLOAD":                "Configuration data was not provided",
	"INVALID_JSON":              "Invalid configuration format",
	"MISSING_INTERFACE":         "Interface name is required",
	"MISSING_MODE":              "Network mode (static/dhcp/pppoe) is required",
	"IF_NOT_FOUND":              "Interface does not exist on this system",
	"PPPOE_USERNAME_REQUIRED":   "PPPoE username is required",
	"PPPOE_PASSWORD_REQUIRED":   "PPPoE password is required for new connections",
	"VLAN_ID_REQUIRED":          "VLAN ID is required when VLAN is enabled",
	"INVALID_VLAN_ID":           "VLAN ID must be between 1 and 4094",
	"INVALID_MODE":              "Invalid network mode specified",
	"INVALID_MTU":               "MTU must be between 576 and 9000",
	"INVALID_MSS":               "MSS must be between 536 and 8960",
	"CONFIG_NOT_FOUND":          "pfSense configuration file not found",
	"READ_FAILED":               "Failed to read configuration file",
	"NO_CONFIG_DATA":            "No configuration data provided for restore",
	"INVALID_XML":               "Invalid XML format in configuration file",
	"NOT_PFSENSE_CONFIG":        "File is not a valid pfSense configuration",
	"BACKUP_FAILED":             "Failed to create configuration backup",
	"WRITE_FAILED":              "Failed to write configuration file",
	"WRITE_VERIFICATION_FAILED": "Configuration file verification failed after write",
	"PARSE_FAILED":              "Failed to parse new configuration",
	"NO_DEFAULT_CONFIG":         "Default configuration not provided",
	"INVALID_DEFAULT_CONFIG":    "Invalid default configuration format",
}

// translatePhpError converts PHP error codes to human-readable messages
func translatePhpError(errStr string) string {
	// Extract error code from "ERROR:CODE" or "ERROR:CODE - details"
	code := strings.TrimPrefix(errStr, "ERROR:")
	if idx := strings.Index(code, " -"); idx >= 0 {
		code = code[:idx]
	}
	code = strings.TrimSpace(code)

	if msg, ok := errorMessages[code]; ok {
		return msg
	}
	// Return original if no translation found
	return errStr
}

// ===================================================================
// DATA STRUCTURES
// ===================================================================

// InterfaceStatus represents the current state of a network interface
type InterfaceStatus struct {
	Name        string `json:"name"`         // Lowercase (wan, lan, opt1)
	DisplayName string `json:"display_name"` // Uppercase for UI (WAN, LAN, OPT1)
	IfObj       string `json:"real_if"`
	IpAddr      string `json:"ipaddr"`
	Subnet      string `json:"subnet"`
	SubnetMask  string `json:"subnet_mask"`
	Gateway     string `json:"gateway"`
	Status      string `json:"status"`
	BytesIn     uint64 `json:"bytes_in"`
	BytesOut    uint64 `json:"bytes_out"`
	Mode        string `json:"mode"`
	Description string `json:"description"`
	MTU         string `json:"mtu"`
	MSS         string `json:"mss"`
	Enabled     bool   `json:"enabled"` // Interface enabled/disabled state

	// PPPoE configuration fields
	PPPoEUsername   string `json:"pppoe_username"`
	PPPoEPassword   string `json:"pppoe_password"` // Will be masked in UI
	PPPoEVlanEnable bool   `json:"pppoe_vlan_enable"`
	PPPoEVlanID     string `json:"pppoe_vlan_id"`
	PPPoEVlanDesc   string `json:"pppoe_vlan_desc"`

	// DHCP Server configuration fields (for Static IP mode)
	DHCPServerEnable bool   `json:"dhcp_server_enable"`
	DHCPLeaseTime    string `json:"dhcp_lease_time"` // in seconds
	DHCPDNS1         string `json:"dhcp_dns1"`
	DHCPDNS2         string `json:"dhcp_dns2"`
	DHCPPoolStart    string `json:"dhcp_pool_start"`
	DHCPPoolEnd      string `json:"dhcp_pool_end"`
}

// ConfigRequest represents a configuration change request
type ConfigRequest struct {
	Interface       string `json:"interface"`
	Mode            string `json:"mode"`
	IpAddr          string `json:"ipaddr"`
	Subnet          string `json:"subnet"`
	Gateway         string `json:"gateway"`
	Description     string `json:"description"`
	MTU             string `json:"mtu"`
	MSS             string `json:"mss"`
	PPPoEUsername   string `json:"pppoe_username"`
	PPPoEPassword   string `json:"pppoe_password"`
	PPPoEVlanEnable bool   `json:"pppoe_vlan_enable"` // Enable VLAN for PPPoE
	PPPoEVlanID     string `json:"pppoe_vlan_id"`     // VLAN tag (1-4094)
	PPPoEVlanDesc   string `json:"pppoe_vlan_desc"`   // VLAN description

	// DHCP Server configuration (for Static IP mode)
	DHCPServerEnable bool   `json:"dhcp_server_enable"`
	DHCPLeaseTime    string `json:"dhcp_lease_time"`
	DHCPDNS1         string `json:"dhcp_dns1"`
	DHCPDNS2         string `json:"dhcp_dns2"`
	DHCPPoolStart    string `json:"dhcp_pool_start"`
	DHCPPoolEnd      string `json:"dhcp_pool_end"`
}

// ===================================================================
// PUBLIC API
// ===================================================================

// GetState fetches current interface status from pfSense
func GetState() (map[string]InterfaceStatus, error) {
	raw, err := runPhp(PhpReadScript, nil)
	if err != nil {
		return nil, err
	}

	// Convert raw map to typed struct
	tmpJson, _ := json.Marshal(raw)
	var result map[string]InterfaceStatus
	if err := json.Unmarshal(tmpJson, &result); err != nil {
		return nil, fmt.Errorf("JSON parse error: %v", err)
	}

	return result, nil
}

// ApplyConfig applies configuration changes to pfSense
func ApplyConfig(req ConfigRequest) error {
	// Convert interface name to lowercase for backend
	req.Interface = strings.ToLower(req.Interface)

	payload, _ := json.Marshal(req)
	_, err := runPhp(PhpWriteScript, map[string]string{
		"NETSHIM_PAYLOAD": string(payload),
	})
	return err
}

// ===================================================================
// INTERNAL PHP EXECUTION
// ===================================================================

// runPhpRaw executes a PHP script and returns raw string output
func runPhpRaw(scriptContent string, env map[string]string) (string, error) {
	// Ensure temp directory exists
	os.MkdirAll(TempDir, 0755)

	// Create temporary PHP file in our persistent directory
	tmpFile, err := os.CreateTemp(TempDir, "netshim_*.php")
	if err != nil {
		// Fallback to /tmp if our directory fails
		tmpFile, err = os.CreateTemp("/tmp", "netshim_*.php")
		if err != nil {
			return "", fmt.Errorf("temp file creation failed: %v", err)
		}
	}
	defer os.Remove(tmpFile.Name())

	// Write script content
	if _, err := tmpFile.WriteString(scriptContent); err != nil {
		return "", fmt.Errorf("script write failed: %v", err)
	}
	tmpFile.Close()

	// Prepare command
	cmd := exec.Command(PhpBinary, tmpFile.Name())
	cmd.Dir = WebDir

	// Set environment variables
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	// Execute PHP script
	out, err := cmd.CombinedOutput()
	outputStr := string(out)

	// Check for PHP execution errors
	if err != nil {
		return "", fmt.Errorf("PHP execution error: %v | Output: %s", err, outputStr)
	}

	// Check for explicit ERROR and translate to user-friendly message
	if strings.HasPrefix(strings.TrimSpace(outputStr), "ERROR:") {
		return "", fmt.Errorf("%s", translatePhpError(strings.TrimSpace(outputStr)))
	}

	return outputStr, nil
}

// runPhp executes a PHP script and returns parsed JSON result
func runPhp(scriptContent string, env map[string]string) (map[string]interface{}, error) {
	// Ensure temp directory exists
	os.MkdirAll(TempDir, 0755)

	// Create temporary PHP file in our persistent directory
	tmpFile, err := os.CreateTemp(TempDir, "netshim_*.php")
	if err != nil {
		// Fallback to /tmp if our directory fails
		tmpFile, err = os.CreateTemp("/tmp", "netshim_*.php")
		if err != nil {
			return nil, fmt.Errorf("temp file creation failed: %v", err)
		}
	}
	defer os.Remove(tmpFile.Name())

	// Write script content
	if _, err := tmpFile.WriteString(scriptContent); err != nil {
		return nil, fmt.Errorf("script write failed: %v", err)
	}
	tmpFile.Close()

	// Prepare command
	cmd := exec.Command(PhpBinary, tmpFile.Name())
	cmd.Dir = WebDir

	// Set environment variables
	cmd.Env = os.Environ()
	for k, v := range env {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}

	// Execute PHP script
	out, err := cmd.CombinedOutput()
	outputStr := string(out)

	// Check for PHP execution errors
	if err != nil {
		return nil, fmt.Errorf("PHP execution error: %v | Output: %s", err, outputStr)
	}

	// ===================================================================
	// HANDLE DIFFERENT OUTPUT TYPES
	// ===================================================================

	// 1. Check for SUCCESS response (write operations)
	if strings.Contains(outputStr, "SUCCESS") {
		return nil, nil
	}

	// 2. Check for explicit ERROR and translate
	if strings.HasPrefix(strings.TrimSpace(outputStr), "ERROR:") {
		return nil, fmt.Errorf("%s", translatePhpError(strings.TrimSpace(outputStr)))
	}

	// 3. Try to parse as JSON (read operations)
	jsonStart := strings.Index(outputStr, "{")
	if jsonStart == -1 {
		if len(strings.TrimSpace(outputStr)) == 0 {
			return nil, fmt.Errorf("empty PHP output")
		}
		return nil, fmt.Errorf("no JSON found in output: %s", outputStr)
	}

	// Extract JSON content
	jsonContent := []byte(outputStr[jsonStart:])

	// Parse JSON
	var result map[string]interface{}
	if err := json.Unmarshal(jsonContent, &result); err != nil {
		return nil, fmt.Errorf("JSON parse failed: %v | Raw output: %s", err, outputStr)
	}

	return result, nil
}

// EnableInterface enables or disables an interface
func EnableInterface(iface string, enabled bool) error {
	enabledStr := "0"
	if enabled {
		enabledStr = "1"
	}

	_, err := runPhp(PhpEnableScript, map[string]string{
		"INTERFACE": strings.ToLower(iface),
		"ENABLED":   enabledStr,
	})

	return err
}

// BackupConfig returns the current pfSense configuration
func BackupConfig() ([]byte, error) {
	output, err := runPhpRaw(PhpBackupScript, nil)
	if err != nil {
		return nil, err
	}
	return []byte(output), nil
}

// RestoreConfig writes a new configuration to pfSense and returns detailed status
func RestoreConfig(configData []byte) (string, error) {
	output, err := runPhpRaw(PhpRestoreScript, map[string]string{
		"NETSHIM_CONFIG_DATA": string(configData),
	})
	if err != nil {
		return "", err
	}
	if !strings.Contains(output, "SUCCESS") {
		return "", fmt.Errorf("restore failed: %s", output)
	}
	// Return the detailed success message (e.g., "SUCCESS:bytes_written=23286,old_rev=123,new_rev=456")
	return strings.TrimSpace(output), nil
}

// ResetConfig restores the default configuration and returns detailed status
func ResetConfig(defaultConfig []byte) (string, error) {
	output, err := runPhpRaw(PhpResetScript, map[string]string{
		"NETSHIM_DEFAULT_CONFIG": string(defaultConfig),
	})
	if err != nil {
		return "", err
	}
	if !strings.Contains(output, "SUCCESS") {
		return "", fmt.Errorf("reset failed: %s", output)
	}
	// Return the detailed success message
	return strings.TrimSpace(output), nil
}

// RebootSystem triggers a system reboot
func RebootSystem() error {
	output, err := runPhpRaw(PhpRebootScript, nil)
	if err != nil {
		return err
	}
	if !strings.Contains(output, "SUCCESS") {
		return fmt.Errorf("reboot failed: %s", output)
	}
	return nil
}

// ShutdownSystem triggers a system shutdown/halt
func ShutdownSystem() error {
	output, err := runPhpRaw(PhpShutdownScript, nil)
	if err != nil {
		return err
	}
	if !strings.Contains(output, "SUCCESS") {
		return fmt.Errorf("shutdown failed: %s", output)
	}
	return nil
}

// ===================================================================
// MONITOR API FUNCTIONS
// ===================================================================

// GatewayStatus represents a single gateway's status
type GatewayStatus struct {
	Name      string `json:"name"`
	Interface string `json:"interface"`
	Gateway   string `json:"gateway"`
	Monitor   string `json:"monitor"`
	Status    string `json:"status"`
	Delay     string `json:"delay"`
	Stddev    string `json:"stddev"`
	Loss      string `json:"loss"`
}

// TrafficData represents WAN interface traffic
type TrafficData struct {
	Interface string `json:"interface"`
	BytesIn   uint64 `json:"bytes_in"`
	BytesOut  uint64 `json:"bytes_out"`
	Timestamp int64  `json:"timestamp"`
}

// GetGatewayStatus fetches gateway status from pfSense
func GetGatewayStatus() ([]GatewayStatus, error) {
	output, err := runPhpRaw(PhpGatewayStatusScript, nil)
	if err != nil {
		return nil, fmt.Errorf("PHP execution failed: %v", err)
	}

	// Check for errors
	if strings.HasPrefix(strings.TrimSpace(output), "ERROR:") {
		errMsg := strings.TrimPrefix(strings.TrimSpace(output), "ERROR:")
		return nil, fmt.Errorf(errMsg)
	}

	// Parse JSON
	var gateways []GatewayStatus
	if err := json.Unmarshal([]byte(output), &gateways); err != nil {
		return nil, fmt.Errorf("JSON parse error: %v", err)
	}

	return gateways, nil
}

// GetWANTraffic fetches WAN interface traffic statistics
func GetWANTraffic() (*TrafficData, error) {
	output, err := runPhpRaw(PhpTrafficStatsScript, nil)
	if err != nil {
		return nil, fmt.Errorf("PHP execution failed: %v", err)
	}

	// Check for errors
	if strings.HasPrefix(strings.TrimSpace(output), "ERROR:") {
		errMsg := strings.TrimPrefix(strings.TrimSpace(output), "ERROR:")
		return nil, fmt.Errorf(errMsg)
	}

	// Parse JSON
	var traffic TrafficData
	if err := json.Unmarshal([]byte(output), &traffic); err != nil {
		return nil, fmt.Errorf("JSON parse error: %v", err)
	}

	return &traffic, nil
}
