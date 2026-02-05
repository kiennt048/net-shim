package adguard

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	BaseURL     string
	Username    string
	Password    string
	InsecureTLS bool
	HTTP        *http.Client
}

func NewClient(baseURL, username, password string, insecureTLS bool) *Client {
	cleanBase := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.HasPrefix(cleanBase, "https://") && insecureTLS {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	return &Client{
		BaseURL:     cleanBase,
		Username:    username,
		Password:    password,
		InsecureTLS: insecureTLS,
		HTTP: &http.Client{
			Timeout:   8 * time.Second,
			Transport: transport,
		},
	}
}

func (c *Client) Status() (*ServerStatus, error) {
	var status ServerStatus
	if err := c.doJSON(http.MethodGet, "/status", nil, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (c *Client) FilteringStatus() (*FilterStatus, error) {
	var status FilterStatus
	if err := c.doJSON(http.MethodGet, "/filtering/status", nil, &status); err != nil {
		return nil, err
	}
	return &status, nil
}

func (c *Client) SetUserRules(rules []string) error {
	payload := SetRulesRequest{Rules: rules}
	return c.doJSON(http.MethodPost, "/filtering/set_rules", payload, nil)
}

func (c *Client) AddFilterURL(name, url string, whitelist bool) error {
	payload := AddUrlRequest{Name: name, URL: url, Whitelist: whitelist}
	return c.doJSON(http.MethodPost, "/filtering/add_url", payload, nil)
}

func (c *Client) RemoveFilterURL(url string, whitelist bool) error {
	payload := RemoveUrlRequest{URL: url, Whitelist: whitelist}
	return c.doJSON(http.MethodPost, "/filtering/remove_url", payload, nil)
}

func (c *Client) SetFilterURL(name, url string, enabled bool, whitelist bool) error {
	payload := FilterSetUrl{
		URL:       url,
		Whitelist: whitelist,
		Data: FilterSetUrlData{
			Enabled: enabled,
			Name:    name,
			URL:     url,
		},
	}
	return c.doJSON(http.MethodPost, "/filtering/set_url", payload, nil)
}

func (c *Client) BlockedServicesAll() (*BlockedServicesAll, error) {
	var resp BlockedServicesAll
	if err := c.doJSON(http.MethodGet, "/blocked_services/all", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) BlockedServicesGet() (*BlockedServicesSchedule, error) {
	var resp BlockedServicesSchedule
	if err := c.doJSON(http.MethodGet, "/blocked_services/get", nil, &resp); err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *Client) BlockedServicesUpdate(ids []string) error {
	payload := BlockedServicesSchedule{IDs: ids}
	return c.doJSON(http.MethodPut, "/blocked_services/update", payload, nil)
}

func (c *Client) QueryLog(limit int) (*QueryLogResponse, error) {
	if limit <= 0 {
		limit = 100
	}

	var resp QueryLogResponse
	path := fmt.Sprintf("/querylog?limit=%d", limit)
	err := c.doJSON(http.MethodGet, path, nil, &resp)
	if err != nil {
		// Fallback for older AdGuard Home API path
		legacyPath := fmt.Sprintf("/control/querylog?limit=%d", limit)
		if legacyErr := c.doJSON(http.MethodGet, legacyPath, nil, &resp); legacyErr != nil {
			return nil, err
		}
	}
	return &resp, nil
}

func (c *Client) doJSON(method, path string, payload interface{}, out interface{}) error {
	if c.BaseURL == "" {
		return fmt.Errorf("adguard base URL not configured")
	}

	var body io.Reader
	if payload != nil {
		buf, err := json.Marshal(payload)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		body = bytes.NewBuffer(buf)
	}

	req, err := http.NewRequest(method, c.BaseURL+path, body)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")

	if c.Username != "" || c.Password != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return fmt.Errorf("adguard api error (%d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	if out == nil {
		return nil
	}

	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}
	return nil
}
