package auth

import (
	"testing"
	"time"
)

// Test session ID generation
func TestGenerateToken(t *testing.T) {
	id1 := generateToken()
	id2 := generateToken()

	if len(id1) == 0 {
		t.Error("Session ID should not be empty")
	}

	if id1 == id2 {
		t.Error("Session IDs should be unique")
	}

	// Session ID should be 64 hex chars (32 bytes)
	if len(id1) != 64 {
		t.Errorf("Expected session ID length 64, got %d", len(id1))
	}
}

// Test rate limiting
func TestRateLimiter_Allow(t *testing.T) {
	ip := "10.0.0.99:12345"

	// First few attempts should be allowed
	for i := 0; i < 5; i++ {
		if !limiter.Allow(ip) {
			t.Fatalf("Attempt %d should be allowed", i+1)
		}
		limiter.RecordFail(ip)
	}

	// After 5 failed attempts, should be rate limited
	if limiter.Allow(ip) {
		t.Error("Expected IP to be rate limited after 5 failed attempts")
	}
}

// Test rate limiter handles IP without port
func TestRateLimiter_IPWithoutPort(t *testing.T) {
	ip := "10.0.0.100" // No port

	// Should not panic or fail
	allowed := limiter.Allow(ip)
	if !allowed {
		t.Error("IP without port should be allowed initially")
	}
}

// Test CheckSession with non-existent session
func TestCheckSession_NonExistent(t *testing.T) {
	valid := CheckSession("nonexistent_session_id_12345")
	if valid {
		t.Error("Non-existent session should return false")
	}
}

// Test session creation and validation
func TestSession_CreateAndCheck(t *testing.T) {
	sessionID := generateToken()

	// Add session manually for testing
	mu.Lock()
	sessions[sessionID] = &Session{
		Username:     "testuser",
		LastActivity: time.Now(),
	}
	mu.Unlock()

	// Session should be valid
	if !CheckSession(sessionID) {
		t.Error("Session should be valid")
	}

	// Cleanup
	mu.Lock()
	delete(sessions, sessionID)
	mu.Unlock()

	// Session should no longer be valid
	if CheckSession(sessionID) {
		t.Error("Deleted session should not be valid")
	}
}

// Test GetUsername with valid session
func TestGetUsername_Valid(t *testing.T) {
	sessionID := generateToken()
	expectedUser := "testuser123"

	// Add session
	mu.Lock()
	sessions[sessionID] = &Session{
		Username:     expectedUser,
		LastActivity: time.Now(),
	}
	mu.Unlock()

	username := GetUsername(sessionID)
	if username != expectedUser {
		t.Errorf("Expected username '%s', got '%s'", expectedUser, username)
	}

	// Cleanup
	mu.Lock()
	delete(sessions, sessionID)
	mu.Unlock()
}

// Test GetUsername with invalid session
func TestGetUsername_Invalid(t *testing.T) {
	username := GetUsername("nonexistent_session")
	if username != "" {
		t.Errorf("Expected empty username for invalid session, got '%s'", username)
	}
}
