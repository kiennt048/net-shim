package auth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// ===================================================================
// PFSENSE CONFIG STRUCTURES
// ===================================================================

type PfSenseConfig struct {
	XMLName xml.Name `xml:"pfsense"`
	System  struct {
		User []PfSenseUser `xml:"user"`
	} `xml:"system"`
}

type PfSenseUser struct {
	Name     string `xml:"name"`
	Bcrypt   string `xml:"bcrypt-hash"`
	Disabled string `xml:"disabled"`
}

// ===================================================================
// SESSION MANAGEMENT
// ===================================================================

type Session struct {
	Username     string
	LastActivity time.Time
}

var (
	sessions = make(map[string]*Session)
	mu       sync.RWMutex
)

// ===================================================================
// RATE LIMITING
// ===================================================================

type RateLimiter struct {
	attempts map[string][]time.Time
	mu       sync.Mutex
}

var limiter = &RateLimiter{attempts: make(map[string][]time.Time)}

// Allow checks if the IP is allowed to attempt login
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Extract IP without port (fix for remoteAddr containing port)
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		host = ip // Fallback if no port
	}

	now := time.Now()
	// Keep only attempts from last 10 minutes
	valid := make([]time.Time, 0)
	for _, t := range rl.attempts[host] {
		if now.Sub(t) < 10*time.Minute {
			valid = append(valid, t)
		}
	}
	rl.attempts[host] = valid

	// Block if more than 5 failed attempts in 10 minutes
	if len(valid) >= 5 {
		return false
	}
	return true
}

// RecordFail records a failed login attempt
func (rl *RateLimiter) RecordFail(ip string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	// Extract IP without port
	host, _, err := net.SplitHostPort(ip)
	if err != nil {
		host = ip
	}

	rl.attempts[host] = append(rl.attempts[host], time.Now())
}

// ===================================================================
// SESSION CLEANUP GOROUTINE
// ===================================================================

func init() {
	// Start background goroutine to clean up expired sessions
	go func() {
		ticker := time.NewTicker(10 * time.Minute)
		defer ticker.Stop()

		for range ticker.C {
			mu.Lock()
			for id, sess := range sessions {
				if time.Since(sess.LastActivity) > 4*time.Hour {
					delete(sessions, id)
				}
			}
			mu.Unlock()
		}
	}()
}

// ===================================================================
// AUTH HANDLERS
// ===================================================================

// LoginHandler processes login form submissions
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	ip := r.RemoteAddr

	// Check rate limit
	if !limiter.Allow(ip) {
		http.Error(w, "Too many failed attempts. Try again later.", 429)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	valid, err := checkPfSenseUser(username, password)

	if !valid || err != nil {
		limiter.RecordFail(ip)
		http.Redirect(w, r, "/login?error=invalid_credentials", http.StatusSeeOther)
		return
	}

	// Create Session
	sessionID := generateToken()
	mu.Lock()
	sessions[sessionID] = &Session{Username: username, LastActivity: time.Now()}
	mu.Unlock()

	// Set secure cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "netshim_sess",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   14400,        // 4 hours
		HttpOnly: true,         // Prevent JavaScript access
		Secure:   r.TLS != nil, // Dynamic: true if HTTPS, false if HTTP
		SameSite: http.SameSiteStrictMode,
	})

	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// LogoutHandler clears the session
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("netshim_sess")
	if err == nil {
		mu.Lock()
		delete(sessions, c.Value)
		mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:   "netshim_sess",
		MaxAge: -1,
		Path:   "/",
	})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ===================================================================
// MIDDLEWARE
// ===================================================================

// RequireLogin is a middleware that checks for valid session
func RequireLogin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("netshim_sess")
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		mu.RLock()
		sess, ok := sessions[c.Value]
		mu.RUnlock()

		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check session expiry
		if time.Since(sess.LastActivity) > 4*time.Hour {
			mu.Lock()
			delete(sessions, c.Value)
			mu.Unlock()
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Update last activity
		mu.Lock()
		sess.LastActivity = time.Now()
		mu.Unlock()

		next(w, r)
	}
}

// CheckSession checks if a session ID is valid (used in login redirect check)
func CheckSession(sessionID string) bool {
	mu.RLock()
	sess, ok := sessions[sessionID]
	mu.RUnlock()

	if !ok {
		return false
	}

	// Check if expired
	return time.Since(sess.LastActivity) <= 4*time.Hour
}

// ===================================================================
// INTERNAL HELPERS
// ===================================================================

// checkPfSenseUser validates credentials against pfSense config.xml
func checkPfSenseUser(u, p string) (bool, error) {
	data, err := os.ReadFile("/cf/conf/config.xml")
	if err != nil {
		return false, fmt.Errorf("read config error: %v", err)
	}

	var cfg PfSenseConfig
	if err := xml.Unmarshal(data, &cfg); err != nil {
		return false, fmt.Errorf("xml parse error: %v", err)
	}

	for _, user := range cfg.System.User {
		if user.Name == u {
			// Check if account is disabled
			if user.Disabled != "" && (user.Disabled == "true" || user.Disabled == "1") {
				return false, fmt.Errorf("account disabled")
			}

			// Check if hash exists
			if user.Bcrypt == "" {
				return false, fmt.Errorf("hash not found")
			}

			// Compare password
			err := bcrypt.CompareHashAndPassword([]byte(user.Bcrypt), []byte(p))
			if err != nil {
				return false, nil // Wrong password
			}
			return true, nil
		}
	}
	return false, fmt.Errorf("user not found")
}

// generateToken creates a secure random session token
func generateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GetUsername retrieves the username associated with a session ID
func GetUsername(sessionID string) string {
	mu.RLock()
	defer mu.RUnlock()
	if sess, ok := sessions[sessionID]; ok {
		return sess.Username
	}
	return ""
}
