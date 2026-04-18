package irrd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.CacheDataDirectory != "data" {
		t.Errorf("expected data dir 'data', got %q", cfg.CacheDataDirectory)
	}
	if cfg.WhoisUpdateInterval != 60 {
		t.Errorf("expected interval 60, got %d", cfg.WhoisUpdateInterval)
	}
	if len(cfg.NRTMv3Upstreams) == 0 {
		t.Error("expected default NRTMv3 upstreams")
	}
	if len(cfg.NRTMv4Upstreams) == 0 {
		t.Error("expected default NRTMv4 upstreams")
	}
	if _, ok := cfg.NRTMv3Upstreams["RADB"]; !ok {
		t.Error("expected RADB in default NRTMv3 upstreams")
	}
	if _, ok := cfg.NRTMv4Upstreams["RIPE"]; !ok {
		t.Error("expected RIPE in default NRTMv4 upstreams")
	}
}

func TestLoadConfig_FileNotFound(t *testing.T) {
	cfg, err := LoadConfig("/tmp/nonexistent-irrd-config-file.json")
	if err != nil {
		t.Fatalf("expected defaults for missing file, got error: %v", err)
	}
	if cfg.CacheDataDirectory != "data" {
		t.Errorf("expected default CacheDataDirectory, got %q", cfg.CacheDataDirectory)
	}
}

func TestLoadConfig_ValidFile(t *testing.T) {
	overrides := map[string]interface{}{
		"cache_data_directory":  "/custom/cache",
		"whois_update_interval": 120,
		"http_endpoint":         "0.0.0.0:9999",
	}
	data, _ := json.Marshal(overrides)

	f, err := os.CreateTemp("", "irrd-config-*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Write(data)
	f.Close()
	defer os.Remove(f.Name())

	cfg, err := LoadConfig(f.Name())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.CacheDataDirectory != "/custom/cache" {
		t.Errorf("expected /custom/cache, got %q", cfg.CacheDataDirectory)
	}
	if cfg.WhoisUpdateInterval != 120 {
		t.Errorf("expected 120, got %d", cfg.WhoisUpdateInterval)
	}
	// Defaults should be preserved for unset fields
	if len(cfg.NRTMv3Upstreams) == 0 {
		t.Error("expected default NRTMv3 upstreams to be preserved")
	}
}

func TestLoadConfig_InvalidJSON(t *testing.T) {
	f, err := os.CreateTemp("", "irrd-config-bad-*.json")
	if err != nil {
		t.Fatal(err)
	}
	f.Write([]byte("{not valid json}"))
	f.Close()
	defer os.Remove(f.Name())

	_, err = LoadConfig(f.Name())
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestCachePath(t *testing.T) {
	cfg := &Config{CacheDataDirectory: "/data"}
	got := cfg.CachePath("RIPE")
	expected := filepath.Join("/data", "RIPE.cache")
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}

func TestDumpDir(t *testing.T) {
	cfg := &Config{CacheDataDirectory: "/data"}
	got := cfg.DumpDir("RIPE")
	expected := filepath.Join("/data", "dump_RIPE")
	if got != expected {
		t.Errorf("expected %q, got %q", expected, got)
	}
}
