package main

import (
	"testing"
)

// Test sanitizeMessage XSS prevention
func TestSanitizeMessage_XSSPrevention(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{"<img src=x onerror=alert(1)>", "&lt;img src=x onerror=alert(1)&gt;"},
		{"Normal message", "Normal message"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := sanitizeMessage(tc.input)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

// Test sanitizeMessage length limit
func TestSanitizeMessage_LengthLimit(t *testing.T) {
	longMessage := ""
	for i := 0; i < 300; i++ {
		longMessage += "a"
	}

	result := sanitizeMessage(longMessage)
	if len(result) > 203 { // 200 + "..."
		t.Errorf("Expected message to be truncated, got length %d", len(result))
	}
}

// Test CSRF token generation
func TestCSRFToken_Generate(t *testing.T) {
	token := generateCSRFToken()

	if len(token) != 64 { // 32 bytes = 64 hex chars
		t.Errorf("Expected token length 64, got %d", len(token))
	}
}

// Test CSRF token validation - tokens should be single-use
func TestCSRFToken_SingleUse(t *testing.T) {
	token := generateCSRFToken()

	// Token should be valid once
	if !validateCSRFToken(token) {
		t.Error("Expected token to be valid on first use")
	}

	// Token should be invalid after use (single-use)
	if validateCSRFToken(token) {
		t.Error("Expected token to be invalid after first use")
	}
}

// Test CSRF token rejects invalid tokens
func TestCSRFToken_RejectsInvalid(t *testing.T) {
	if validateCSRFToken("invalid_token_12345") {
		t.Error("Expected invalid token to be rejected")
	}

	if validateCSRFToken("") {
		t.Error("Expected empty token to be rejected")
	}
}

// Test CSRF tokens are unique
func TestCSRFToken_Uniqueness(t *testing.T) {
	token1 := generateCSRFToken()
	token2 := generateCSRFToken()

	if token1 == token2 {
		t.Error("CSRF tokens should be unique")
	}
}
