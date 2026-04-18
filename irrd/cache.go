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

	"github.com/jlaffaye/ftp"
)

const userAgent = "gotinyirrdbcache"

var (
	ErrCacheNotReady = errors.New("cache not ready")
	ErrCacheError    = errors.New("cache error")
)

// httpGet performs an HTTP GET with the application User-Agent header.
func httpGet(url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	return http.DefaultClient.Do(req)
}

// WhoisCache manages a single upstream IRRD cache, including persistence,
// synchronisation via NRTMv3 or NRTMv4 updates, and full dump downloads.
type WhoisCache struct {
	Name      string
	NRTMv3    *NRTMv3Config // set for NRTMv3 upstreams
	NRTMv4    *NRTMv4Config // set for NRTMv4 upstreams
	State     *WhoisCacheState
	Ready     bool
	cachePath string
	cfg       *Config
}

// NewNRTMv3Cache creates a new cache manager for an NRTMv3 upstream.
func NewNRTMv3Cache(v3 NRTMv3Config, cfg *Config) *WhoisCache {
	return &WhoisCache{
		Name:      v3.Name,
		NRTMv3:    &v3,
		State:     NewWhoisCacheState(),
		cachePath: cfg.CachePath(v3.Name),
		cfg:       cfg,
	}
}

// NewNRTMv4Cache creates a new cache manager for an NRTMv4 upstream.
func NewNRTMv4Cache(v4 NRTMv4Config, cfg *Config) *WhoisCache {
	return &WhoisCache{
		Name:      v4.Name,
		NRTMv4:    &v4,
		State:     NewWhoisCacheState(),
		cachePath: cfg.CachePath(v4.Name),
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
		log.Printf("Corrupt cache file %s: %v — removing", c.cachePath, err)
		os.Remove(c.cachePath)
		c.State = NewWhoisCacheState()
		c.Ready = false
		cacheCorruptTotal.WithLabelValues(c.Name).Inc()
		return ErrCacheNotReady
	}
	c.State = state
	c.Ready = true
	return nil
}

// Update performs a full update cycle: restore from disk if needed,
// then use the appropriate protocol (NRTMv3 or NRTMv4).
func (c *WhoisCache) Update() error {
	// Try to restore from disk if we have no serial
	if c.State.Serial == "" {
		if _, err := os.Stat(c.cachePath); err == nil {
			log.Printf("Restoring state from %s", c.cachePath)
			state, err := loadState(c.cachePath)
			if err != nil {
				log.Printf("Corrupt cache file %s: %v — removing", c.cachePath, err)
				os.Remove(c.cachePath)
				cacheCorruptTotal.WithLabelValues(c.Name).Inc()
			} else {
				c.State = state
				c.Ready = true
			}
		}
	}

	if c.NRTMv4 != nil {
		return c.updateViaV4()
	}
	return c.updateViaV3()
}

// updateViaV4 handles the NRTMv4 update path (snapshots + deltas).
func (c *WhoisCache) updateViaV4() error {
	err := c.updateNRTMv4()
	if err != nil {
		return fmt.Errorf("NRTMv4 update failed: %w", err)
	}
	c.Ready = true
	log.Printf("Loaded state@%s", c.State.Serial)
	return nil
}

// updateViaV3 handles the NRTMv3 update path (incremental + dump fallback).
func (c *WhoisCache) updateViaV3() error {
	inSync := false

	// If we have a serial, try incremental NRTMv3 update
	if c.State.Serial != "" {
		err := c.updateNRTMv3()
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
			case errors.As(err, &sre):
				serial, _ := strconv.Atoi(c.State.Serial)
				if serial == sre.Last {
					log.Printf("No newer realtime updates available.")
					inSync = true
					c.Ready = true
				} else {
					log.Printf("Near realtime updates out of sync: %v", err)
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

// updateNRTMv3 fetches incremental updates from the upstream IRRD NRTMv3 service.
func (c *WhoisCache) updateNRTMv3() error {
	addr := fmt.Sprintf("%s:%d", c.NRTMv3.Host, c.NRTMv3.Port)
	log.Printf("Connecting to %s", addr)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("connecting to %s: %w", addr, err)
	}
	defer conn.Close()

	serial, _ := strconv.Atoi(c.State.Serial)
	req := fmt.Sprintf("-g %s:3:%d-LAST\n", c.Name, serial+1)
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
	dumpDir := c.cfg.DumpDir(c.Name)
	if err := os.MkdirAll(dumpDir, 0o755); err != nil {
		return "", "", err
	}

	serialURI, err := url.Parse(c.NRTMv3.SerialURI)
	if err != nil {
		return "", "", err
	}
	dumpURI, err := url.Parse(c.NRTMv3.DumpURI)
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
	log.Printf("Downloading %s", c.NRTMv3.SerialURI)
	if err := downloadFile(serialPath, c.NRTMv3.SerialURI); err != nil {
		return "", "", fmt.Errorf("downloading serial: %w", err)
	}

	data, err := os.ReadFile(serialPath)
	if err != nil {
		return "", "", err
	}
	newSerial := strings.TrimSpace(string(data))

	// Download dump if serial changed
	if newSerial != existingSerial {
		log.Printf("Downloading %s", c.NRTMv3.DumpURI)
		if err := downloadFile(dumpPath, c.NRTMv3.DumpURI); err != nil {
			return "", "", fmt.Errorf("downloading dump: %w", err)
		}
	}

	return newSerial, dumpPath, nil
}

// downloadFile downloads a file from a URI (HTTP, HTTPS, or FTP).
func downloadFile(dest, uri string) error {
	_ = os.Remove(dest)
	tmp := dest + ".part"

	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("parsing URI %s: %w", uri, err)
	}

	var reader io.ReadCloser

	switch parsed.Scheme {
	case "http", "https":
		resp, err := httpGet(uri)
		if err != nil {
			return fmt.Errorf("HTTP GET %s: %w", uri, err)
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			return fmt.Errorf("HTTP GET %s: status %d", uri, resp.StatusCode)
		}
		reader = resp.Body
	case "ftp":
		r, err := downloadFTP(parsed)
		if err != nil {
			return fmt.Errorf("FTP %s: %w", uri, err)
		}
		reader = r
	default:
		return fmt.Errorf("unsupported URI scheme: %s", parsed.Scheme)
	}
	defer reader.Close()

	f, err := os.Create(tmp)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, reader); err != nil {
		f.Close()
		return fmt.Errorf("writing %s: %w", tmp, err)
	}
	if err := f.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, dest)
}

// downloadFTP connects to an FTP server and retrieves a file, returning a ReadCloser.
func downloadFTP(u *url.URL) (io.ReadCloser, error) {
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":21"
	}

	conn, err := ftp.Dial(host)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", host, err)
	}

	if err := conn.Login("anonymous", "anonymous@"); err != nil {
		conn.Quit()
		return nil, fmt.Errorf("login: %w", err)
	}

	resp, err := conn.Retr(u.Path)
	if err != nil {
		conn.Quit()
		return nil, fmt.Errorf("retrieving %s: %w", u.Path, err)
	}

	// Wrap to close both the response and the connection
	return &ftpReadCloser{resp: resp, conn: conn}, nil
}

// ftpReadCloser wraps an FTP response to clean up the connection on close.
type ftpReadCloser struct {
	resp *ftp.Response
	conn *ftp.ServerConn
}

func (f *ftpReadCloser) Read(p []byte) (int, error) {
	return f.resp.Read(p)
}

func (f *ftpReadCloser) Close() error {
	err := f.resp.Close()
	f.conn.Quit()
	return err
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
