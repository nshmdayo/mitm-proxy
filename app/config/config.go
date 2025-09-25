package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Addr         string       `yaml:"addr"`
	MockServer   bool         `yaml:"mock_server"`
	Mitm         MitmConfig   `yaml:"mitm"`
	Modification ModConfig    `yaml:"modification"`
}

type MitmConfig struct {
	Enabled   bool   `yaml:"enabled"`
	PersistCA bool   `yaml:"persist_ca"`
	CertDir   string `yaml:"cert_dir"`
}

type ModConfig struct {
	Enabled bool `yaml:"enabled"`
	Verbose bool `yaml:"verbose"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	err = yaml.Unmarshal(data, &cfg)
	if err != nil {
		return nil, err
	}

	return &cfg, nil
}
