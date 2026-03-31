package irrd

import (
	"compress/gzip"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var (
	ErrCacheNotReady = errors.New("cache not ready")
	ErrCacheError    = errors.New("cache error")
)

// WhoisCache manages a single upstream IRRD cache, including persistence,
// synchronisation via telnet updates, and full dump downloads.
type WhoisCache struct {
	Config    UpstreamConfig
	State     *WhoisCacheState
	Ready     bool
	cachePath string
	cfg       *Config
}

// NewWhoisCache creates a new cache manager for an upstream.
func NewWhoisCache(upstream UpstreamConfig, cfg *Config) *WhoisCache {
	return &WhoisCache{
		Config:    upstream,
		State:     NewWhoisCacheState(),
		Ready:     false,
		cachePath: cfg.CachePath(upstream.Name),
		cfg:       cfg,
	}
}

// Load restores serialized cache state from disk without updating.
func (c *WhoisCache) Load() error {
	if _, err := os.Stat(c.cachePath); os.IsNotExist(err) {
		return ErrCacheNotReady
	}
	log.Printf("Restoring state from %s", c.cachePath)
	state, err := loadState(c.cachePath)
	if err != nil {
		return fmt.Errorf("loading cache state: %w", err)
	}
	c.State = state
	c.Ready = true
	return nil
}

// Update performs a full update cycle: restore from disk if needed, try telnet
// incremental update, fall back to full dump download if out of sync.
func (c *WhoisCache) Update() error {
	inSync := false

	// Try to restore from disk if we have no serial
	if c.State.Serial == "" {
		if _, err := os.Stat(c.cachePath); err == nil {
			log.Printf("Restoring state from %s", c.cachePath)
			state, err := loadState(c.cachePath)
			if err == nil {
				c.State = state
				c.Ready = true
			}
		}
	}

	// If we have a serial, try incremental telnet update
	if c.State.Serial != "" {
		err := c.updateTelnet()
		if err == nil {
			inSync = true
			c.Ready = true
		} else {
			var oose *OutOfSyncError
			var sre *SerialRangeError
			var er *ErrorResponse

			switch {
			case errors.As(err, &oose):
				log.Printf("Near realtime updates out of sync. Downloading dump.")
				inSync = false
				c.Ready = false
			case errors.As(err, &sre):
				serial, _ := strconv.Atoi(c.State.Serial)
				if serial == sre.Last {
					log.Printf("No newer realtime updates available.")
					inSync = true
					c.Ready = true
				} else {
					log.Printf("Near realtime updates out of sync: %v", err)
					inSync = false
					c.Ready = false
				}
			case errors.As(err, &er):
				log.Printf("Error in realtime update: %v", err)
			default:
				log.Printf("Error in realtime update: %v", err)
			}
		}
	}

	// Fall back to full dump if not in sync
	if !inSync {
		freshState := NewWhoisCacheState()
		if err := c.updateDump(freshState); err != nil {
			return fmt.Errorf("dump update failed: %w", err)
		}
		c.State = freshState
		c.Ready = true
	}

	log.Printf("Loaded state@%s", c.State.Serial)
	return nil
}

// Save persists the current cache state to disk.
func (c *WhoisCache) Save() error {
	log.Printf("Saving state@%s to %s", c.State.Serial, c.cachePath)
	tmpPath := c.cachePath + ".update"
	if err := saveState(c.State, tmpPath); err != nil {
		return err
	}
	return os.Rename(tmpPath, c.cachePath)
}

// updateTelnet fetches incremental updates from the upstream IRRD telnet service.
func (c *WhoisCache) updateTelnet() error {
	addr := fmt.Sprintf("%s:%d", c.Config.TelnetHost, c.Config.TelnetPort)
	log.Printf("Connecting to %s", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	serial, _ := strconv.Atoi(c.State.Serial)
	req := fmt.Sprintf("-g %s:3:%d-LAST\n", c.Config.Name, serial+1)
	log.Printf("Sending %s", strings.TrimSpace(req))
	if _, err := fmt.Fprint(conn, req); err != nil {
		return fmt.Errorf("sending request: %w", err)
	}

	updates, err := ParseUpdates(conn)
	if err != nil {
		return err
	}

	for _, u := range updates {
		c.State.ApplyUpdate(u)
	}

	if len(updates) > 0 {
		return c.Save()
	}
	log.Printf("No new updates")
	return nil
}

// updateDump downloads and loads a full database dump into the given state.
func (c *WhoisCache) updateDump(state *WhoisCacheState) error {
	serial, dumpPath, err := c.downloadDump()
	if err != nil {
		return err
	}
	if serial == state.Serial {
		return nil
	}
	if err := c.loadDump(state, serial, dumpPath); err != nil {
		return err
	}
	// Save after loading dump
	origState := c.State
	c.State = state
	err = c.Save()
	c.State = origState
	return err
}

// loadDump parses a dump file and applies all records as ADD updates.
func (c *WhoisCache) loadDump(state *WhoisCacheState, serial string, dumpPath string) error {
	log.Printf("Loading dump at %s", dumpPath)

	f, err := os.Open(dumpPath)
	if err != nil {
		return err
	}
	defer f.Close()

	var r io.Reader = f
	if strings.HasSuffix(dumpPath, ".gz") {
		gr, err := gzip.NewReader(f)
		if err != nil {
			return fmt.Errorf("opening gzip reader: %w", err)
		}
		defer gr.Close()
		r = gr
	}

	records, err := ParseDump(r)
	if err != nil {
		return fmt.Errorf("parsing dump: %w", err)
	}

	for _, rec := range records {
		state.ApplyUpdate(Update{Action: "ADD", Serial: serial, Record: rec})
	}
	return nil
}

// downloadDump downloads the latest serial and dump file from the upstream.
func (c *WhoisCache) downloadDump() (serial string, dumpPath string, err error) {
	dumpDir := c.cfg.DumpDir(c.Config.Name)
	if err := os.MkdirAll(dumpDir, 0o755); err != nil {
		return "", "", err
	}

	serialURI, err := url.Parse(c.Config.SerialURI)
	if err != nil {
		return "", "", err
	}
	dumpURI, err := url.Parse(c.Config.DumpURI)
	if err != nil {
		return "", "", err
	}

	serialPath := filepath.Join(dumpDir, filepath.Base(serialURI.Path))
	dumpPath = filepath.Join(dumpDir, filepath.Base(dumpURI.Path))

	// Read existing serial if available
	var existingSerial string
	if data, err := os.ReadFile(serialPath); err == nil {
		existingSerial = strings.TrimSpace(string(data))
	}

	// Download serial file
	log.Printf("Downloading %s", c.Config.SerialURI)
	if err := downloadFile(serialPath, c.Config.SerialURI); err != nil {
		return "", "", fmt.Errorf("downloading serial: %w", err)
	}

	data, err := os.ReadFile(serialPath)
	if err != nil {
		return "", "", err
	}
	newSerial := strings.TrimSpace(string(data))

	// Download dump if serial changed
	if newSerial != existingSerial {
		log.Printf("Downloading %s", c.Config.DumpURI)
		if err := downloadFile(dumpPath, c.Config.DumpURI); err != nil {
			return "", "", fmt.Errorf("downloading dump: %w", err)
		}
	}

	return newSerial, dumpPath, nil
}

// downloadFile downloads a file from a URI using net/http.
func downloadFile(dest, uri string) error {
	_ = os.Remove(dest)
	tmp := dest + ".part"

	log.Printf("Downloading %s", uri)
	resp, err := http.Get(uri)
	if err != nil {
		return fmt.Errorf("HTTP GET %s: %w", uri, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP GET %s: status %d", uri, resp.StatusCode)
	}

	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, dest)
}

// loadState deserializes a WhoisCacheState from a gob-encoded file.
func loadState(path string) (*WhoisCacheState, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	state := &WhoisCacheState{}
	if err := gob.NewDecoder(f).Decode(state); err != nil {
		return nil, err
	}
	return state, nil
}

// saveState serializes a WhoisCacheState to a gob-encoded file.
func saveState(state *WhoisCacheState, path string) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()

	return gob.NewEncoder(f).Encode(state)
}
