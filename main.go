package main

import (
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"io"
	"log"
	"net"
	"net-shim/internal/auth"
	"net-shim/internal/pfsense"
	netshimtls "net-shim/internal/tls"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Version info - injected at build time via ldflags
var (
	Version   = "dev"     // Set by -ldflags "-X main.Version=..."
	BuildTime = "unknown" // Set by -ldflags "-X main.BuildTime=..."
	BuildNum  = "0"       // Set by -ldflags "-X main.BuildNum=..."
)

// GetVersion returns the full version string
func GetVersion() string {
	if Version == "dev" {
		return "dev"
	}
	return fmt.Sprintf("v%s.%s_%s", Version, BuildNum, BuildTime)
}

//go:embed templates/*.html
var content embed.FS

//go:embed defaults/config.xml
var defaultConfig embed.FS

// ===================================================================
// TEMPLATE HELPERS
// ===================================================================

// sortedInterfaceKeys returns interface names in preferred order:
// WAN first, LAN second, then others alphabetically
func sortedInterfaceKeys(m map[string]pfsense.InterfaceStatus) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	// Custom sort: WAN first, then LAN, then others alphabetically
	sort.Slice(keys, func(i, j int) bool {
		priority := map[string]int{"wan": 0, "lan": 1}
		pi, oki := priority[keys[i]]
		pj, okj := priority[keys[j]]
		if oki && okj {
			return pi < pj
		}
		if oki {
			return true
		}
		if okj {
			return false
		}
		return keys[i] < keys[j]
	})

	return keys
}

var funcMap = template.FuncMap{
	"upper":      strings.ToUpper,
	"lower":      strings.ToLower,
	"sortedKeys": sortedInterfaceKeys,
}

// ===================================================================
// DATA STRUCTURES
// ===================================================================

type IndexData struct {
	Username       string
	Interfaces     map[string]pfsense.InterfaceStatus
	LastMsg        string
	IsError        bool
	CSRFToken      string
	ShowRebootBtn  bool
	IsRebooting    bool
	IsShuttingDown bool
}

type LoginData struct {
	Error   string
	Version string
}

type PageData struct {
	Title string
	IndexData
	LoginData
}

// Stats API response with error handling
type StatsResponse struct {
	Interfaces map[string]pfsense.InterfaceStatus `json:"interfaces"`
	Error      string                             `json:"error,omitempty"`
	Timestamp  int64                              `json:"timestamp"`
}

// ===================================================================
// STATS CACHING (5-second TTL for 1-5 users)
// ===================================================================

var (
	statsCache      *StatsResponse
	statsCacheMutex sync.RWMutex
	statsCacheTime  time.Time
)

// ===================================================================
// CSRF PROTECTION
// ===================================================================

var (
	csrfTokens      = make(map[string]time.Time)
	csrfTokensMutex sync.RWMutex
)

// generateCSRFToken creates a new CSRF token and stores it
func generateCSRFToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	token := hex.EncodeToString(b)

	csrfTokensMutex.Lock()
	csrfTokens[token] = time.Now()
	csrfTokensMutex.Unlock()

	return token
}

// validateCSRFToken checks if a token is valid and removes it (single use)
func validateCSRFToken(token string) bool {
	csrfTokensMutex.Lock()
	defer csrfTokensMutex.Unlock()

	createdAt, exists := csrfTokens[token]
	if !exists {
		return false
	}

	// Token expires after 1 hour
	if time.Since(createdAt) > time.Hour {
		delete(csrfTokens, token)
		return false
	}

	// Remove token after use (single-use tokens)
	delete(csrfTokens, token)
	return true
}

// cleanupCSRFTokens removes expired tokens (called periodically)
func init() {
	go func() {
		ticker := time.NewTicker(30 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			csrfTokensMutex.Lock()
			for token, createdAt := range csrfTokens {
				if time.Since(createdAt) > time.Hour {
					delete(csrfTokens, token)
				}
			}
			csrfTokensMutex.Unlock()
		}
	}()
}

// ===================================================================
// INPUT VALIDATION
// ===================================================================

var (
	ifaceNameRegex = regexp.MustCompile(`^[a-z][a-z0-9_]{0,15}$`)
	ipv4Regex      = regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	safeTextRegex  = regexp.MustCompile(`^[a-zA-Z0-9\s\-_.]{0,255}$`)
)

// validateConfigRequest validates all user inputs before sending to PHP
func validateConfigRequest(req *pfsense.ConfigRequest) error {
	// 1. Interface name validation
	if !ifaceNameRegex.MatchString(req.Interface) {
		return &ValidationError{"Invalid interface name format"}
	}

	// 2. Mode validation
	validModes := map[string]bool{"static": true, "dhcp": true, "pppoe": true}
	if !validModes[req.Mode] {
		return &ValidationError{"Invalid mode - must be static, dhcp, or pppoe"}
	}

	// 3. Static mode specific validations
	if req.Mode == "static" {
		// IP Address required
		if req.IpAddr == "" {
			return &ValidationError{"IP address required for static mode"}
		}
		if !ipv4Regex.MatchString(req.IpAddr) {
			return &ValidationError{"Invalid IP address format"}
		}
		ip := net.ParseIP(req.IpAddr)
		if ip == nil || ip.To4() == nil {
			return &ValidationError{"Invalid IPv4 address"}
		}

		// Subnet validation
		subnet, err := strconv.Atoi(req.Subnet)
		if err != nil || subnet < 0 || subnet > 32 {
			return &ValidationError{"Subnet must be 0-32"}
		}

		// Gateway validation (optional but validate if provided)
		if req.Gateway != "" {
			if !ipv4Regex.MatchString(req.Gateway) {
				return &ValidationError{"Invalid gateway format"}
			}
			gw := net.ParseIP(req.Gateway)
			if gw == nil || gw.To4() == nil {
				return &ValidationError{"Invalid gateway IPv4 address"}
			}
		}
	}

	// 4. PPPoE specific validations
	if req.Mode == "pppoe" {
		// Username required
		if req.PPPoEUsername == "" {
			return &ValidationError{"PPPoE username required"}
		}
		// Password is validated in PHP (required for new configs, optional for updates)

		// VLAN validation (if enabled)
		if req.PPPoEVlanEnable {
			if req.PPPoEVlanID == "" {
				return &ValidationError{"VLAN ID required when VLAN is enabled"}
			}
			vlanID, err := strconv.Atoi(req.PPPoEVlanID)
			if err != nil || vlanID < 1 || vlanID > 4094 {
				return &ValidationError{"VLAN ID must be between 1 and 4094"}
			}
		}
	}

	// 5. DHCP Server specific validations (for static mode only)
	if req.Mode == "static" && req.DHCPServerEnable {
		// Pool start IP validation (optional, will auto-fill in PHP)
		if req.DHCPPoolStart != "" {
			if !ipv4Regex.MatchString(req.DHCPPoolStart) {
				return &ValidationError{"Invalid DHCP pool start IP format"}
			}
			poolStart := net.ParseIP(req.DHCPPoolStart)
			if poolStart == nil || poolStart.To4() == nil {
				return &ValidationError{"Invalid DHCP pool start IPv4 address"}
			}
		}

		// Pool end IP validation (optional, will auto-fill in PHP)
		if req.DHCPPoolEnd != "" {
			if !ipv4Regex.MatchString(req.DHCPPoolEnd) {
				return &ValidationError{"Invalid DHCP pool end IP format"}
			}
			poolEnd := net.ParseIP(req.DHCPPoolEnd)
			if poolEnd == nil || poolEnd.To4() == nil {
				return &ValidationError{"Invalid DHCP pool end IPv4 address"}
			}
		}

		// Lease time validation (optional but validate if provided)
		if req.DHCPLeaseTime != "" {
			leaseTime, err := strconv.Atoi(req.DHCPLeaseTime)
			if err != nil || leaseTime < 60 || leaseTime > 604800 {
				return &ValidationError{"DHCP lease time must be 60-604800 seconds (1 min to 1 week)"}
			}
		}

		// DNS validation (optional but validate if provided)
		if req.DHCPDNS1 != "" {
			if !ipv4Regex.MatchString(req.DHCPDNS1) {
				return &ValidationError{"Invalid DNS 1 format"}
			}
			dns1 := net.ParseIP(req.DHCPDNS1)
			if dns1 == nil || dns1.To4() == nil {
				return &ValidationError{"Invalid DNS 1 IPv4 address"}
			}
		}
		if req.DHCPDNS2 != "" {
			if !ipv4Regex.MatchString(req.DHCPDNS2) {
				return &ValidationError{"Invalid DNS 2 format"}
			}
			dns2 := net.ParseIP(req.DHCPDNS2)
			if dns2 == nil || dns2.To4() == nil {
				return &ValidationError{"Invalid DNS 2 IPv4 address"}
			}
		}
	}

	// 6. Description sanitization
	if req.Description != "" {
		if !safeTextRegex.MatchString(req.Description) {
			return &ValidationError{"Description contains invalid characters"}
		}
		if len(req.Description) > 255 {
			req.Description = req.Description[:255]
		}
	}

	// 7. MTU validation (optional, 576-9000 bytes)
	if req.MTU != "" {
		mtu, err := strconv.Atoi(req.MTU)
		if err != nil || mtu < 576 || mtu > 9000 {
			return &ValidationError{"MTU must be 576-9000"}
		}
	}

	// 8. MSS validation (optional, 536-8960 bytes)
	if req.MSS != "" {
		mss, err := strconv.Atoi(req.MSS)
		if err != nil || mss < 536 || mss > 8960 {
			return &ValidationError{"MSS must be 536-8960"}
		}
	}

	return nil
}

// ValidationError wraps validation errors
type ValidationError struct {
	Message string
}

func (e *ValidationError) Error() string {
	return e.Message
}

// ===================================================================
// SECURITY HELPERS
// ===================================================================

// sanitizeMessage cleans error messages before displaying to users
// Prevents XSS attacks via error message injection
func sanitizeMessage(msg string) string {
	// HTML escape to prevent script injection
	msg = html.EscapeString(msg)

	// Limit length to prevent UI breaking
	if len(msg) > 200 {
		msg = msg[:200] + "..."
	}

	return msg
}

// ===================================================================
// TEMPLATE RENDERING (FIXED - NO COLLISION)
// ===================================================================

// render parses ONLY the required templates for each request to avoid collision
// This prevents the "content" block collision between index.html and login.html
func render(w http.ResponseWriter, pageName string, data PageData) {
	// CRITICAL: Parse layout.html + specific page ONLY (not all templates)
	// This ensures each page's "content" block doesn't overwrite others
	tmpl, err := template.New("base").Funcs(funcMap).ParseFS(content,
		"templates/layout.html",
		"templates/"+pageName)

	if err != nil {
		log.Printf("❌ Template parse error: %v", err)
		http.Error(w, "Internal Server Error", 500)
		return
	}

	// Execute the "base" template (layout.html)
	// This will include the "content" block from the specific page
	err = tmpl.ExecuteTemplate(w, "base", data)
	if err != nil {
		log.Printf("❌ Template execution error: %v", err)
		http.Error(w, "Internal Server Error", 500)
	}
}

// ===================================================================
// HTTP HANDLERS
// ===================================================================

func main() {
	// --- INIT MODE: restore default config and reboot (single reboot) ---
	if len(os.Args) > 1 && os.Args[1] == "--init" {
		log.Println("🔧 Init mode: restoring default configuration...")

		defaultConfigData, err := defaultConfig.ReadFile("defaults/config.xml")
		if err != nil {
			log.Fatalf("❌ Failed to read embedded default config: %v", err)
		}

		// Step 1: Restore default config (writes config.xml, reloads, applies filters+interfaces)
		result, err := pfsense.ResetConfig(defaultConfigData)
		if err != nil {
			log.Fatalf("❌ Config restore failed: %v", err)
		}
		log.Printf("✅ Config restored: %s", result)

		fmt.Println("SUCCESS:INIT_COMPLETE")
		os.Exit(0)
	}

	// --- LOGIN ROUTES ---
	http.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			// If already logged in, redirect to dashboard
			if cookie, err := r.Cookie("netshim_sess"); err == nil {
				if auth.CheckSession(cookie.Value) {
					http.Redirect(w, r, "/", http.StatusSeeOther)
					return
				}
			}

			// Show login form with error message if present
			errMsg := ""
			if r.URL.Query().Get("error") == "invalid_credentials" {
				errMsg = "Invalid username or password"
			}

			render(w, "login.html", PageData{
				Title:     "Login",
				LoginData: LoginData{Error: errMsg, Version: GetVersion()},
			})
			return
		}

		// POST: Handle login submission
		auth.LoginHandler(w, r)
	})

	http.HandleFunc("/logout", auth.LogoutHandler)

	// --- DASHBOARD ---
	http.HandleFunc("/", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("netshim_sess")
		username := auth.GetUsername(cookie.Value)

		if username == "" {
			username = "Admin"
		}

		// Fetch interface data
		ifData, err := pfsense.GetState()

		// Parse message from query parameter
		msg := r.URL.Query().Get("msg")
		lastMsg := ""
		isErr := false

		if msg == "success" {
			lastMsg = "✅ Configuration applied successfully"
		} else if strings.HasPrefix(msg, "error:") {
			isErr = true
			rawMsg := strings.TrimPrefix(msg, "error:")
			lastMsg = sanitizeMessage(rawMsg) // ← SECURITY: Prevent XSS
		} else if err != nil {
			isErr = true
			lastMsg = "⚠️ System Error: Unable to fetch interface status"
			log.Printf("❌ GetState error: %v", err)
		}

		// Generate CSRF token for forms
		csrfToken := generateCSRFToken()

		render(w, "index.html", PageData{
			Title: "Dashboard",
			IndexData: IndexData{
				Username:   username,
				Interfaces: ifData,
				LastMsg:    lastMsg,
				IsError:    isErr,
				CSRFToken:  csrfToken,
			},
		})
	}))

	// --- APPLY CONFIGURATION ---
	http.HandleFunc("/apply", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "405 Method Not Allowed", 405)
			return
		}

		// Get username for logging
		cookie, _ := r.Cookie("netshim_sess")
		username := auth.GetUsername(cookie.Value)

		// ← SECURITY: Validate CSRF token
		csrfToken := r.FormValue("csrf_token")
		if !validateCSRFToken(csrfToken) {
			log.Printf("⚠️ CSRF validation failed (user=%s, ip=%s)", username, r.RemoteAddr)
			http.Redirect(w, r, "/?msg=error:Security validation failed. Please refresh and try again.", http.StatusSeeOther)
			return
		}

		// Parse form data
		req := pfsense.ConfigRequest{
			Interface:        r.FormValue("interface"),
			Mode:             r.FormValue("mode"),
			IpAddr:           r.FormValue("ipaddr"),
			Subnet:           r.FormValue("subnet"),
			Gateway:          r.FormValue("gateway"),
			Description:      r.FormValue("description"),
			MTU:              r.FormValue("mtu"),
			MSS:              r.FormValue("mss"),
			PPPoEUsername:    r.FormValue("pppoe_username"),
			PPPoEPassword:    r.FormValue("pppoe_password"),
			PPPoEVlanEnable:  r.FormValue("pppoe_vlan_enable") == "on",
			PPPoEVlanID:      r.FormValue("pppoe_vlan_id"),
			PPPoEVlanDesc:    r.FormValue("pppoe_vlan_desc"),
			DHCPServerEnable: r.FormValue("dhcp_server_enable") == "on",
			DHCPLeaseTime:    r.FormValue("dhcp_lease_time"),
			DHCPDNS1:         r.FormValue("dhcp_dns1"),
			DHCPDNS2:         r.FormValue("dhcp_dns2"),
			DHCPPoolStart:    r.FormValue("dhcp_pool_start"),
			DHCPPoolEnd:      r.FormValue("dhcp_pool_end"),
		}

		// ← SECURITY: Validate all inputs
		if err := validateConfigRequest(&req); err != nil {
			log.Printf("⚠️ Validation failed: %v (user=%s, ip=%s)", err, username, r.RemoteAddr)
			http.Redirect(w, r, "/?msg=error:"+err.Error(), http.StatusSeeOther)
			return
		}

		// Apply configuration via PHP
		if err := pfsense.ApplyConfig(req); err != nil {
			log.Printf("❌ Config apply failed: %v (user=%s, interface=%s, mode=%s)",
				err, username, req.Interface, req.Mode)
			http.Redirect(w, r, "/?msg=error:Configuration failed", http.StatusSeeOther)
			return
		}

		log.Printf("✅ Config applied successfully (user=%s, interface=%s, mode=%s)",
			username, req.Interface, req.Mode)
		http.Redirect(w, r, "/?msg=success", http.StatusSeeOther)
	}))

	// --- STATS API (for bandwidth monitoring) ---
	http.HandleFunc("/stats", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		// Check cache first (5-second TTL)
		statsCacheMutex.RLock()
		if statsCache != nil && time.Since(statsCacheTime) < 5*time.Second {
			cached := statsCache
			statsCacheMutex.RUnlock()

			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "private, max-age=5")
			json.NewEncoder(w).Encode(cached)
			return
		}
		statsCacheMutex.RUnlock()

		// Fetch fresh data from pfSense
		ifData, err := pfsense.GetState()

		response := &StatsResponse{
			Interfaces: ifData,
			Timestamp:  time.Now().Unix(),
		}

		if err != nil {
			log.Printf("⚠️ Stats fetch error: %v", err)
			response.Error = "Failed to fetch interface stats"
			// Return empty map instead of nil to prevent frontend crashes
			response.Interfaces = make(map[string]pfsense.InterfaceStatus)
		}

		// Update cache
		statsCacheMutex.Lock()
		statsCache = response
		statsCacheTime = time.Now()
		statsCacheMutex.Unlock()

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "private, max-age=5")
		json.NewEncoder(w).Encode(response)
	}))

	// --- INTERFACE ENABLE/DISABLE ---
	http.HandleFunc("/interface/toggle", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cookie, _ := r.Cookie("netshim_sess")
		username := auth.GetUsername(cookie.Value)

		// ← SECURITY: Validate CSRF token
		csrfToken := r.FormValue("csrf_token")
		if !validateCSRFToken(csrfToken) {
			log.Printf("⚠️ CSRF validation failed for toggle (user=%s, ip=%s)", username, r.RemoteAddr)
			http.Redirect(w, r, "/?msg=error:Security validation failed. Please refresh and try again.", http.StatusSeeOther)
			return
		}

		ifName := strings.ToLower(r.FormValue("interface"))
		enabledStr := r.FormValue("enabled")
		enabled := enabledStr == "1"

		log.Printf("🔄 Interface toggle: %s → %s (user=%s, ip=%s)",
			ifName, map[bool]string{true: "ENABLED", false: "DISABLED"}[enabled],
			username, r.RemoteAddr)

		// Apply enable/disable
		if err := pfsense.EnableInterface(ifName, enabled); err != nil {
			log.Printf("❌ Interface toggle failed: %v (interface=%s)", err, ifName)
			http.Redirect(w, r, "/?msg=error:Failed to toggle interface", http.StatusSeeOther)
			return
		}

		// Success - redirect with message
		msg := "Interface " + strings.ToUpper(ifName) + " "
		if enabled {
			msg += "enabled successfully"
		} else {
			msg += "disabled successfully"
		}
		log.Printf("✅ Interface toggle success: %s (user=%s)", ifName, username)
		http.Redirect(w, r, "/?msg=success:"+msg, http.StatusSeeOther)
	}))

	// --- MONITOR API: Gateway Status ---
	http.HandleFunc("/api/monitor/gateways", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		gateways, err := pfsense.GetGatewayStatus()
		if err != nil {
			log.Printf("⚠️ Gateway status error: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error":    err.Error(),
				"gateways": []interface{}{},
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"gateways": gateways,
		})
	}))

	// --- MONITOR API: WAN Traffic ---
	http.HandleFunc("/api/monitor/traffic", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		traffic, err := pfsense.GetWANTraffic()
		if err != nil {
			log.Printf("⚠️ Traffic stats error: %v", err)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": err.Error(),
			})
			return
		}

		json.NewEncoder(w).Encode(traffic)
	}))

	// --- MONITOR PAGE ---
	http.HandleFunc("/monitor", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("netshim_sess")
		username := auth.GetUsername(cookie.Value)

		render(w, "monitor.html", PageData{
			Title: "Monitor",
			IndexData: IndexData{
				Username: username,
			},
		})
	}))

	// --- BACKUP PAGE ---
	http.HandleFunc("/backup", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("netshim_sess")
		username := auth.GetUsername(cookie.Value)

		// Parse message from query parameter
		msg := r.URL.Query().Get("msg")
		lastMsg := ""
		isErr := false
		showRebootBtn := false
		isRebooting := false
		isShuttingDown := false

		if msg == "success" {
			lastMsg = "✅ Operation completed successfully"
		} else if strings.HasPrefix(msg, "success:") {
			lastMsg = "✅ " + strings.TrimPrefix(msg, "success:")
		} else if strings.HasPrefix(msg, "error:") {
			isErr = true
			lastMsg = "⚠️ " + sanitizeMessage(strings.TrimPrefix(msg, "error:"))
		} else if strings.HasPrefix(msg, "reboot:") {
			// Reboot recommended - show warning and button
			lastMsg = "🔄 " + strings.TrimPrefix(msg, "reboot:")
			showRebootBtn = true
		} else if strings.HasPrefix(msg, "rebooting:") {
			// System is rebooting
			lastMsg = "🔄 " + strings.TrimPrefix(msg, "rebooting:")
			isRebooting = true
		} else if strings.HasPrefix(msg, "shutdown:") {
			// System is shutting down
			lastMsg = "⏻ " + strings.TrimPrefix(msg, "shutdown:")
			isShuttingDown = true
		}

		// Generate CSRF token for forms
		csrfToken := generateCSRFToken()

		render(w, "backup.html", PageData{
			Title: "Backup & Restore",
			IndexData: IndexData{
				Username:       username,
				LastMsg:        lastMsg,
				IsError:        isErr,
				CSRFToken:      csrfToken,
				ShowRebootBtn:  showRebootBtn,
				IsRebooting:    isRebooting,
				IsShuttingDown: isShuttingDown,
			},
		})
	}))

	// --- BACKUP DOWNLOAD ---
	http.HandleFunc("/backup/download", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		cookie, _ := r.Cookie("netshim_sess")
		username := auth.GetUsername(cookie.Value)

		log.Printf("📥 Backup download requested (user=%s, ip=%s)", username, r.RemoteAddr)

		configData, err := pfsense.BackupConfig()
		if err != nil {
			log.Printf("❌ Backup download failed: %v (user=%s)", err, username)
			http.Error(w, "Failed to download backup", http.StatusInternalServerError)
			return
		}

		// Set headers for download
		w.Header().Set("Content-Type", "application/xml")
		w.Header().Set("Content-Disposition", "attachment; filename=config-"+time.Now().Format("2006-01-02-150405")+".xml")
		w.Header().Set("Content-Length", strconv.Itoa(len(configData)))
		w.Write(configData)

		log.Printf("✅ Backup downloaded successfully (user=%s, size=%d)", username, len(configData))
	}))

	// --- BACKUP RESTORE ---
	http.HandleFunc("/backup/restore", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cookie, _ := r.Cookie("netshim_sess")
		username := auth.GetUsername(cookie.Value)

		// Validate CSRF token
		csrfToken := r.FormValue("csrf_token")
		if !validateCSRFToken(csrfToken) {
			log.Printf("⚠️ CSRF validation failed for restore (user=%s, ip=%s)", username, r.RemoteAddr)
			http.Redirect(w, r, "/backup?msg=error:Security validation failed", http.StatusSeeOther)
			return
		}

		// Parse multipart form (5MB limit)
		if err := r.ParseMultipartForm(5 << 20); err != nil {
			log.Printf("⚠️ Form parsing failed: %v (user=%s)", err, username)
			http.Redirect(w, r, "/backup?msg=error:File too large (max 5MB)", http.StatusSeeOther)
			return
		}

		// Get uploaded file
		file, header, err := r.FormFile("config_file")
		if err != nil {
			log.Printf("⚠️ File upload failed: %v (user=%s)", err, username)
			http.Redirect(w, r, "/backup?msg=error:No file uploaded", http.StatusSeeOther)
			return
		}
		defer file.Close()

		// Validate file extension
		if !strings.HasSuffix(strings.ToLower(header.Filename), ".xml") {
			http.Redirect(w, r, "/backup?msg=error:Invalid file type (must be .xml)", http.StatusSeeOther)
			return
		}

		// Read file content
		configData, err := io.ReadAll(file)
		if err != nil {
			log.Printf("❌ File read failed: %v (user=%s)", err, username)
			http.Redirect(w, r, "/backup?msg=error:Failed to read file", http.StatusSeeOther)
			return
		}

		log.Printf("📤 Restore requested (user=%s, ip=%s, file=%s, size=%d)",
			username, r.RemoteAddr, header.Filename, len(configData))

		// Restore the configuration
		result, err := pfsense.RestoreConfig(configData)
		if err != nil {
			log.Printf("❌ Restore failed: %v (user=%s)", err, username)
			http.Redirect(w, r, "/backup?msg=error:Restore failed - "+err.Error(), http.StatusSeeOther)
			return
		}

		log.Printf("✅ Configuration restored (user=%s, file=%s, result=%s)", username, header.Filename, result)
		http.Redirect(w, r, "/backup?msg=reboot:Configuration restored successfully. Reboot is recommended.", http.StatusSeeOther)
	}))

	// --- BACKUP RESET TO DEFAULT ---
	http.HandleFunc("/backup/reset", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cookie, _ := r.Cookie("netshim_sess")
		username := auth.GetUsername(cookie.Value)

		// Validate CSRF token
		csrfToken := r.FormValue("csrf_token")
		if !validateCSRFToken(csrfToken) {
			log.Printf("⚠️ CSRF validation failed for reset (user=%s, ip=%s)", username, r.RemoteAddr)
			http.Redirect(w, r, "/backup?msg=error:Security validation failed", http.StatusSeeOther)
			return
		}

		log.Printf("🔄 Factory reset requested (user=%s, ip=%s)", username, r.RemoteAddr)

		// Read default config from embedded file
		defaultConfigData, err := defaultConfig.ReadFile("defaults/config.xml")
		if err != nil {
			log.Printf("❌ Default config not found: %v", err)
			http.Redirect(w, r, "/backup?msg=error:Default configuration not found", http.StatusSeeOther)
			return
		}

		// Reset to default
		result, err := pfsense.ResetConfig(defaultConfigData)
		if err != nil {
			log.Printf("❌ Reset failed: %v (user=%s)", err, username)
			http.Redirect(w, r, "/backup?msg=error:Reset failed - "+err.Error(), http.StatusSeeOther)
			return
		}

		log.Printf("✅ Factory reset completed (user=%s, result=%s)", username, result)
		http.Redirect(w, r, "/backup?msg=reboot:System reset to factory defaults. Reboot is recommended.", http.StatusSeeOther)
	}))

	// --- SYSTEM REBOOT ---
	http.HandleFunc("/system/reboot", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cookie, _ := r.Cookie("netshim_sess")
		username := auth.GetUsername(cookie.Value)

		// Validate CSRF token
		csrfToken := r.FormValue("csrf_token")
		if !validateCSRFToken(csrfToken) {
			log.Printf("⚠️ CSRF validation failed for reboot (user=%s, ip=%s)", username, r.RemoteAddr)
			http.Redirect(w, r, "/backup?msg=error:Security validation failed", http.StatusSeeOther)
			return
		}

		log.Printf("🔄 System reboot requested (user=%s, ip=%s)", username, r.RemoteAddr)

		// Trigger reboot
		if err := pfsense.RebootSystem(); err != nil {
			log.Printf("❌ Reboot failed: %v (user=%s)", err, username)
			http.Redirect(w, r, "/backup?msg=error:Reboot failed - "+err.Error(), http.StatusSeeOther)
			return
		}

		log.Printf("✅ System reboot initiated (user=%s)", username)
		// Show rebooting message - the system will go down shortly
		http.Redirect(w, r, "/backup?msg=rebooting:System is rebooting. Please wait...", http.StatusSeeOther)
	}))

	// --- SYSTEM SHUTDOWN ---
	http.HandleFunc("/system/shutdown", auth.RequireLogin(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		cookie, _ := r.Cookie("netshim_sess")
		username := auth.GetUsername(cookie.Value)

		// Validate CSRF token
		csrfToken := r.FormValue("csrf_token")
		if !validateCSRFToken(csrfToken) {
			log.Printf("⚠️ CSRF validation failed for shutdown (user=%s, ip=%s)", username, r.RemoteAddr)
			http.Redirect(w, r, "/backup?msg=error:Security validation failed", http.StatusSeeOther)
			return
		}

		log.Printf("⏻ System shutdown requested (user=%s, ip=%s)", username, r.RemoteAddr)

		// Trigger shutdown
		if err := pfsense.ShutdownSystem(); err != nil {
			log.Printf("❌ Shutdown failed: %v (user=%s)", err, username)
			http.Redirect(w, r, "/backup?msg=error:Shutdown failed - "+err.Error(), http.StatusSeeOther)
			return
		}

		log.Printf("✅ System shutdown initiated (user=%s)", username)
		// Show shutdown message - the system will power off shortly
		http.Redirect(w, r, "/backup?msg=shutdown:System is shutting down...", http.StatusSeeOther)
	}))

	// --- HEALTH CHECK ENDPOINT ---
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	// --- VERSION ENDPOINT ---
	http.HandleFunc("/version", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{
			"version":    GetVersion(),
			"base":       Version,
			"build":      BuildNum,
			"build_time": BuildTime,
		})
	})

	// --- START SERVER ---
	log.Printf("🚀 BEYONDNET Firewall Control %s", GetVersion())
	log.Println("🔒 pfSense Integration: ENABLED")
	log.Println("🛡️  CSRF Protection: ENABLED")

	// Try HTTPS with self-signed certificate
	certPath, keyPath, tlsErr := netshimtls.EnsureCert()
	if tlsErr != nil {
		log.Printf("⚠️ TLS setup failed: %v", tlsErr)
		log.Println("📡 Falling back to HTTP on :8080")
		log.Fatal(http.ListenAndServe("0.0.0.0:8080", nil))
	} else {
		log.Println("🔐 HTTPS enabled with self-signed certificate")
		log.Println("📡 Listening on https://0.0.0.0:8443")
		log.Println("📡 Also listening on http://0.0.0.0:8080 (redirects to HTTPS)")

		// Start HTTP redirect server in background
		go func() {
			redirectHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Serve health check directly (needed for install script)
				if r.URL.Path == "/health" {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("OK"))
					return
				}
				// Redirect everything else to HTTPS
				host := r.Host
				if h, _, err := net.SplitHostPort(r.Host); err == nil {
					host = h
				}
				target := "https://" + host + ":8443" + r.URL.Path
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				http.Redirect(w, r, target, http.StatusMovedPermanently)
			})
			http.ListenAndServe("0.0.0.0:8080", redirectHandler)
		}()

		log.Fatal(http.ListenAndServeTLS("0.0.0.0:8443", certPath, keyPath, nil))
	}
}
