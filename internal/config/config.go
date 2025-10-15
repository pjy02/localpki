package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
)

// Config describes the runtime configuration for the online CA service.
type Config struct {
	BindAddress  string             `json:"bind_address"`
	TLS          TLSConfig          `json:"tls"`
	Database     Database           `json:"database"`
	Intermediate Intermediate       `json:"intermediate"`
	Profiles     map[string]Profile `json:"profiles"`
	Security     Security           `json:"security"`
	ACME         ACMEConfig         `json:"acme"`
}

// TLSConfig holds HTTPS certificate options for the management UI/API.
type TLSConfig struct {
	CertPath string `json:"cert_path"`
	KeyPath  string `json:"key_path"`
}

// Database represents persistent state configuration.
type Database struct {
	Path string `json:"path"`
}

// Intermediate describes the intermediate CA material used for signing.
type Intermediate struct {
	CertPath       string `json:"cert_path"`
	KeyPath        string `json:"key_path"`
	KeyPassword    string `json:"key_password"`
	ChainPath      string `json:"chain_path"`
	DefaultProfile string `json:"default_profile"`
}

// Profile defines signing defaults for issued certificates.
type Profile struct {
	Name            string   `json:"name"`
	ValidityDays    int      `json:"validity_days"`
	KeyUsage        []string `json:"key_usage"`
	ExtKeyUsage     []string `json:"ext_key_usage"`
	AllowClientAuth bool     `json:"allow_client_auth"`
}

// Security configures WebAuthn and session handling.
type Security struct {
	RPName         string   `json:"rp_name"`
	RPID           string   `json:"rp_id"`
	RPOrigins      []string `json:"rp_origins"`
	SessionMinutes int      `json:"session_minutes"`
}

// ACMEConfig controls the optional ACME service.
type ACMEConfig struct {
	Enabled        bool   `json:"enabled"`
	BasePath       string `json:"base_path"`
	DefaultProfile string `json:"default_profile"`
}

// Load reads a configuration file (JSON syntax; JSON 也是合法 YAML)。
func Load(path string) (*Config, error) {
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.BindAddress == "" {
		cfg.BindAddress = "127.0.0.1:8443"
	}
	if cfg.Intermediate.DefaultProfile == "" {
		cfg.Intermediate.DefaultProfile = "server-tls"
	}
	if cfg.Profiles == nil {
		cfg.Profiles = make(map[string]Profile)
	}
	if cfg.Security.RPName == "" {
		cfg.Security.RPName = "LocalPKI"
	}
	if cfg.Security.RPID == "" {
		cfg.Security.RPID = "localhost"
	}
	if len(cfg.Security.RPOrigins) == 0 {
		cfg.Security.RPOrigins = []string{"https://localhost:8443"}
	}
	if cfg.Security.SessionMinutes <= 0 {
		cfg.Security.SessionMinutes = 30
	}
	if cfg.ACME.BasePath == "" {
		cfg.ACME.BasePath = "/acme/local"
	}
	if cfg.ACME.DefaultProfile == "" {
		cfg.ACME.DefaultProfile = cfg.Intermediate.DefaultProfile
	}
	return &cfg, nil
}
