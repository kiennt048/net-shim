package webfilter

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	DefaultAdGuardURL     = "http://127.0.0.1:3000"
	DefaultDNSTargetPort  = 5353
	DefaultRedirectIface  = "lan"
	DefaultRedirectTarget = "lanip"
)

type Config struct {
	AdGuardURL        string   `json:"adguard_url"`
	AdGuardUsername   string   `json:"adguard_username"`
	AdGuardPassword   string   `json:"adguard_password"`
	DNSTargetPort     int      `json:"dns_target_port"`
	RedirectInterface string   `json:"redirect_interface"`
	RedirectTarget    string   `json:"redirect_target"`
	ForceDNS          bool     `json:"force_dns"`
	AutoDisable       bool     `json:"auto_disable"`
	AutoHeal          bool     `json:"auto_heal"`
	BlockDoH          bool     `json:"block_doh"`
	BlockDoT          bool     `json:"block_dot"`
	DoHHosts          []string `json:"doh_hosts"`
	AllowInsecureTLS  bool     `json:"allow_insecure_tls"`
}

func DefaultConfig() *Config {
	return &Config{
		AdGuardURL:        DefaultAdGuardURL,
		AdGuardUsername:   "",
		AdGuardPassword:   "",
		DNSTargetPort:     DefaultDNSTargetPort,
		RedirectInterface: DefaultRedirectIface,
		RedirectTarget:    DefaultRedirectTarget,
		ForceDNS:          true,
		AutoDisable:       true,
		AutoHeal:          true,
		BlockDoH:          true,
		BlockDoT:          true,
		DoHHosts:          DefaultDoHHosts(),
		AllowInsecureTLS:  true,
	}
}

func ConfigPath() string {
	if override := os.Getenv("NETSHIM_WEBFILTER_CONFIG"); override != "" {
		return override
	}
	return "/usr/local/share/netshim/webfilter.json"
}

func LoadConfig() (*Config, error) {
	path := ConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			cfg := DefaultConfig()
			if saveErr := SaveConfig(cfg); saveErr != nil {
				return cfg, saveErr
			}
			return cfg, nil
		}
		return nil, fmt.Errorf("read config: %w", err)
	}

	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	applyDefaults(&cfg)
	return &cfg, nil
}

func SaveConfig(cfg *Config) error {
	path := ConfigPath()
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}

	applyDefaults(cfg)
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config: %w", err)
	}
	return nil
}

func applyDefaults(cfg *Config) {
	if cfg.AdGuardURL == "" {
		cfg.AdGuardURL = DefaultAdGuardURL
	}
	if cfg.DNSTargetPort == 0 {
		cfg.DNSTargetPort = DefaultDNSTargetPort
	}
	if cfg.RedirectInterface == "" {
		cfg.RedirectInterface = DefaultRedirectIface
	}
	if cfg.RedirectTarget == "" {
		cfg.RedirectTarget = DefaultRedirectTarget
	}
	if len(cfg.DoHHosts) == 0 {
		cfg.DoHHosts = DefaultDoHHosts()
	}
}
