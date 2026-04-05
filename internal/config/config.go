package config

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

type Config struct {
	// Proxy settings
	ListenAddr string `json:"listen_addr"`
	AdminAddr  string `json:"admin_addr"`

	// TLS/MITM settings
	EnableMITM bool   `json:"enable_mitm"`
	CAKeyFile  string `json:"ca_key_file"`
	CACertFile string `json:"ca_cert_file"`

	// Logging settings
	LogDir        string `json:"log_dir"`
	LogMaxSizeMB  int    `json:"log_max_size_mb"`
	LogMaxBackups int    `json:"log_max_backups"`
	LogBodyLimit  int    `json:"log_body_limit"`  // max body bytes to log (0 = unlimited)
	LogFormat     string `json:"log_format"`      // "json" or "text"

	// Filter settings
	BlockedHosts []string `json:"blocked_hosts"`
}

func DefaultConfig() *Config {
	return &Config{
		ListenAddr:    ":8080",
		AdminAddr:     ":8081",
		EnableMITM:    true,
		CAKeyFile:     "certs/ca.key",
		CACertFile:    "certs/ca.crt",
		LogDir:        "logs",
		LogMaxSizeMB:  100,
		LogMaxBackups: 10,
		LogBodyLimit:  64 * 1024, // 64KB
		LogFormat:     "json",
	}
}

func Load() (*Config, error) {
	cfg := DefaultConfig()

	configFile := flag.String("config", "", "Path to config file (JSON)")
	listenAddr := flag.String("listen", "", "Proxy listen address (e.g. :8080)")
	adminAddr := flag.String("admin", "", "Admin API listen address (e.g. :8081)")
	enableMITM := flag.Bool("mitm", true, "Enable MITM for HTTPS inspection")
	logDir := flag.String("log-dir", "", "Log directory")
	logFormat := flag.String("log-format", "", "Log format: json or text")
	flag.Parse()

	// Load from config file if specified
	if *configFile != "" {
		data, err := os.ReadFile(*configFile)
		if err != nil {
			return nil, fmt.Errorf("read config file: %w", err)
		}
		if err := json.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config file: %w", err)
		}
	}

	// CLI flags override config file
	if *listenAddr != "" {
		cfg.ListenAddr = *listenAddr
	}
	if *adminAddr != "" {
		cfg.AdminAddr = *adminAddr
	}
	cfg.EnableMITM = *enableMITM
	if *logDir != "" {
		cfg.LogDir = *logDir
	}
	if *logFormat != "" {
		cfg.LogFormat = *logFormat
	}

	return cfg, nil
}
