package irrd

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// UpstreamConfig defines a single IRRD upstream source.
type UpstreamConfig struct {
	Name       string `json:"name"`
	DumpURI    string `json:"dump_uri"`
	SerialURI  string `json:"serial_uri"`
	TelnetHost string `json:"telnet_host"`
	TelnetPort int    `json:"telnet_port"`
}

// Config holds all application settings.
type Config struct {
	CacheDataDirectory  string                    `json:"cache_data_directory"`
	WhoisUpdateInterval int                       `json:"whois_update_interval"` // seconds
	HTTPEndpoint        string                    `json:"http_endpoint"`
	Upstreams           map[string]UpstreamConfig `json:"upstreams"`
}

// DefaultConfig returns the default configuration with standard IRRD upstreams.
func DefaultConfig() *Config {
	return &Config{
		CacheDataDirectory:  "data",
		WhoisUpdateInterval: 60,
		HTTPEndpoint:        "0.0.0.0:8087",
		Upstreams: map[string]UpstreamConfig{
			"RADB": {
				Name:       "RADB",
				DumpURI:    "ftp://ftp.radb.net/radb/dbase/radb.db.gz",
				SerialURI:  "ftp://ftp.radb.net/radb/dbase/RADB.CURRENTSERIAL",
				TelnetHost: "whois.radb.net",
				TelnetPort: 43,
			},
			"RIPE": {
				Name:       "RIPE",
				DumpURI:    "https://ftp.ripe.net/ripe/dbase/ripe.db.gz",
				SerialURI:  "https://ftp.ripe.net/ripe/dbase/RIPE.CURRENTSERIAL",
				TelnetHost: "nrtm.db.ripe.net",
				TelnetPort: 4444,
			},
		},
	}
}

// LoadConfig reads a JSON config file and merges it with defaults.
// If the file does not exist, defaults are returned.
func LoadConfig(path string) (*Config, error) {
	cfg := DefaultConfig()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// CachePath returns the file path for a named cache's serialized state.
func (c *Config) CachePath(name string) string {
	return filepath.Join(c.CacheDataDirectory, name+".cache")
}

// DumpDir returns the directory path for a named cache's dump files.
func (c *Config) DumpDir(name string) string {
	return filepath.Join(c.CacheDataDirectory, "dump_"+name)
}
