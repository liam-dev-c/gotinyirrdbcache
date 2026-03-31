package irrd

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// NRTMv3Config holds settings for an NRTMv3 upstream source.
type NRTMv3Config struct {
	Name      string `json:"name"`
	DumpURI   string `json:"dump_uri"`
	SerialURI string `json:"serial_uri"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
}

// NRTMv4Config holds settings for an NRTMv4 upstream source.
type NRTMv4Config struct {
	Name            string `json:"name"`
	NotificationURI string `json:"notification_uri"`         // Update Notification File URL
	PublicKey       string `json:"public_key,omitempty"`     // Ed25519 or ES256 public key, base64-encoded (inline)
	PublicKeyURI    string `json:"public_key_uri,omitempty"` // URL to fetch PEM-encoded public key
}

// Config holds all application settings.
type Config struct {
	CacheDataDirectory  string                  `json:"cache_data_directory"`
	WhoisUpdateInterval int                     `json:"whois_update_interval"` // seconds
	HTTPEndpoint        string                  `json:"http_endpoint"`
	NRTMv3Upstreams     map[string]NRTMv3Config `json:"nrtmv3_upstreams"`
	NRTMv4Upstreams     map[string]NRTMv4Config `json:"nrtmv4_upstreams"`
}

// DefaultConfig returns the default configuration with standard IRRD upstreams.
func DefaultConfig() *Config {
	return &Config{
		CacheDataDirectory:  "data",
		WhoisUpdateInterval: 60,
		HTTPEndpoint:        "0.0.0.0:8087",
		NRTMv3Upstreams: map[string]NRTMv3Config{},
		NRTMv4Upstreams: map[string]NRTMv4Config{
			"RIPE": {
				Name:            "RIPE",
				NotificationURI: "https://nrtm.db.ripe.net/nrtmv4/RIPE/update-notification-file.jose",
				PublicKeyURI:    "https://ftp.ripe.net/ripe/dbase/nrtmv4/nrtmv4_public_key.txt",
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
