package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Create a temporary directory
	tempDir := t.TempDir()

	// 1. Test Valid Config
	validConfig := `
addr: ":8080"
mock_server: true
mitm:
  enabled: true
  persist_ca: true
  cert_dir: "./certs"
modification:
  enabled: true
  verbose: true
`
	validFile := filepath.Join(tempDir, "valid.yaml")
	if err := os.WriteFile(validFile, []byte(validConfig), 0644); err != nil {
		t.Fatalf("Failed to write valid config file: %v", err)
	}

	cfg, err := LoadConfig(validFile)
	if err != nil {
		t.Errorf("LoadConfig failed for valid config: %v", err)
	}
	if cfg.Addr != ":8080" {
		t.Errorf("Expected Addr ':8080', got '%s'", cfg.Addr)
	}
	if !cfg.MockServer {
		t.Error("Expected MockServer to be true")
	}
	if !cfg.Mitm.Enabled {
		t.Error("Expected Mitm.Enabled to be true")
	}
	if cfg.Mitm.CertDir != "./certs" {
		t.Errorf("Expected Mitm.CertDir './certs', got '%s'", cfg.Mitm.CertDir)
	}

	// 2. Test Non-existent File
	_, err = LoadConfig(filepath.Join(tempDir, "nonexistent.yaml"))
	if err == nil {
		t.Error("Expected error for non-existent file, got nil")
	}

	// 3. Test Invalid YAML
	invalidConfig := `
addr: ":8080"
mock_server: "invalid_boolean"
`
	invalidFile := filepath.Join(tempDir, "invalid.yaml")
	if err := os.WriteFile(invalidFile, []byte(invalidConfig), 0644); err != nil {
		t.Fatalf("Failed to write invalid config file: %v", err)
	}

	_, err = LoadConfig(invalidFile)
	if err == nil {
		t.Error("Expected error for invalid YAML, got nil")
	}
}
