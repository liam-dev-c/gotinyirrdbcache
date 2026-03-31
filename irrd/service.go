package irrd

import (
	"fmt"
	"log"
	"net/http"
	"time"
)

// CacheStateProvider is the interface for accessing cache state.
// Both WhoisCacheState and CacheStateCombiner satisfy this via duck typing,
// so we define a common interface for the web layer.
type CacheStateProvider interface {
	GetSerial() string
	GetUpdatedAt() string
	GetMacros() MapAccessor
	GetPrefix4() MapAccessor
	GetPrefix6() MapAccessor
}

// MapAccessor provides dict-like access to string-keyed string-set maps.
type MapAccessor interface {
	Lookup(key string) ([]string, bool)
	Keys() []string
	Items() []MapEntry
}

// MapEntry is a key-value pair for iteration.
type MapEntry struct {
	Key   string
	Value []string
}

// Ensure WhoisCacheState implements CacheStateProvider.
func (s *WhoisCacheState) GetSerial() string    { return s.Serial }
func (s *WhoisCacheState) GetUpdatedAt() string { return s.UpdatedAt.String() }
func (s *WhoisCacheState) GetMacros() MapAccessor  { return &directMap{m: s.Macros} }
func (s *WhoisCacheState) GetPrefix4() MapAccessor  { return &directMap{m: s.Prefix4} }
func (s *WhoisCacheState) GetPrefix6() MapAccessor  { return &directMap{m: s.Prefix6} }

// directMap wraps map[string]StringSet as a MapAccessor.
type directMap struct {
	m map[string]StringSet
}

func (d *directMap) Lookup(key string) ([]string, bool) {
	s, ok := d.m[key]
	if !ok {
		return nil, false
	}
	return s.Slice(), true
}

func (d *directMap) Keys() []string {
	keys := make([]string, 0, len(d.m))
	for k := range d.m {
		keys = append(keys, k)
	}
	return keys
}

func (d *directMap) Items() []MapEntry {
	entries := make([]MapEntry, 0, len(d.m))
	for k, v := range d.m {
		entries = append(entries, MapEntry{Key: k, Value: v.Slice()})
	}
	return entries
}

// Ensure CacheStateCombiner implements CacheStateProvider.
func (c *CacheStateCombiner) GetSerial() string    { return c.Serial }
func (c *CacheStateCombiner) GetUpdatedAt() string { return c.UpdatedAt }
func (c *CacheStateCombiner) GetMacros() MapAccessor  { return &combinerMap[StringSet]{c: c.Macros} }
func (c *CacheStateCombiner) GetPrefix4() MapAccessor  { return &combinerMap[StringSet]{c: c.Prefix4} }
func (c *CacheStateCombiner) GetPrefix6() MapAccessor  { return &combinerMap[StringSet]{c: c.Prefix6} }

// combinerMap wraps CombinerDict[StringSet] as a MapAccessor.
type combinerMap[V ~map[string]struct{}] struct {
	c *CombinerDict[V]
}

func (cm *combinerMap[V]) Lookup(key string) ([]string, bool) {
	v, ok := cm.c.Get(key)
	if !ok {
		return nil, false
	}
	s := StringSet(v)
	return s.Slice(), true
}

func (cm *combinerMap[V]) Keys() []string {
	return cm.c.Keys()
}

func (cm *combinerMap[V]) Items() []MapEntry {
	items := cm.c.Items()
	entries := make([]MapEntry, len(items))
	for i, item := range items {
		s := StringSet(item.Value)
		entries[i] = MapEntry{Key: item.Key, Value: s.Slice()}
	}
	return entries
}

// WhoisCacheService is the web-side service that loads caches from disk
// and serves their state to the HTTP API.
type WhoisCacheService struct {
	Caches map[string]*WhoisCache
	cfg    *Config
}

// NewWhoisCacheService creates a service that loads all caches from disk.
func NewWhoisCacheService(cfg *Config) *WhoisCacheService {
	svc := &WhoisCacheService{
		Caches: make(map[string]*WhoisCache),
		cfg:    cfg,
	}
	for _, up := range cfg.Upstreams {
		cache := NewWhoisCache(up, cfg)
		log.Printf("Loading cache: %s", cache.Config.Name)
		if err := cache.Load(); err != nil {
			log.Printf("Error loading cache %s: %v", cache.Config.Name, err)
		}
		svc.Caches[up.Name] = cache
	}
	log.Printf("Caches initialized")
	return svc
}

// UpdateCache reloads a named cache from disk.
func (svc *WhoisCacheService) UpdateCache(name string) error {
	cache, ok := svc.Caches[name]
	if !ok {
		return fmt.Errorf("no such cache: %s", name)
	}
	log.Printf("Reloading cache: %s", name)
	return cache.Load()
}

// GetCacheState returns the state provider for a named cache.
// The special name "ALL" returns a combined view of all caches.
func (svc *WhoisCacheService) GetCacheState(name string) (CacheStateProvider, error) {
	if name == "ALL" {
		states := make(map[string]*WhoisCacheState)
		for n, c := range svc.Caches {
			states[n] = c.State
		}
		return NewCacheStateCombiner(states), nil
	}

	cache, ok := svc.Caches[name]
	if !ok {
		return nil, fmt.Errorf("no such cache: %s", name)
	}
	if !cache.Ready {
		return nil, ErrCacheNotReady
	}
	return cache.State, nil
}

// WhoisCacheUpdateService is the background daemon that keeps caches
// up to date via telnet updates and dump downloads.
type WhoisCacheUpdateService struct {
	Caches map[string]*WhoisCache
	cfg    *Config
}

// NewWhoisCacheUpdateService creates an update service for all configured upstreams.
func NewWhoisCacheUpdateService(cfg *Config) *WhoisCacheUpdateService {
	svc := &WhoisCacheUpdateService{
		Caches: make(map[string]*WhoisCache),
		cfg:    cfg,
	}
	for _, up := range cfg.Upstreams {
		svc.Caches[up.Name] = NewWhoisCache(up, cfg)
	}
	return svc
}

// Start runs the initial update of all caches, then enters an infinite loop
// updating each cache at the configured interval. The initial update is fatal
// on error. Subsequent update errors are logged but not fatal.
func (svc *WhoisCacheUpdateService) Start() error {
	// Initial update - errors are fatal
	for _, cache := range svc.Caches {
		if err := cache.Update(); err != nil {
			return fmt.Errorf("initial update of %s failed: %w", cache.Config.Name, err)
		}
		svc.notifyWeb(cache.Config.Name)
	}
	log.Printf("Caches initialised")

	// Update loop
	for {
		time.Sleep(time.Duration(svc.cfg.WhoisUpdateInterval) * time.Second)
		for _, cache := range svc.Caches {
			log.Printf("Updating cache: %s", cache.Config.Name)
			if err := cache.Update(); err != nil {
				log.Printf("Error updating cache %s: %v", cache.Config.Name, err)
				continue
			}
			svc.notifyWeb(cache.Config.Name)
		}
	}
}

// notifyWeb triggers the web service to reload a cache from disk.
func (svc *WhoisCacheUpdateService) notifyWeb(name string) {
	url := fmt.Sprintf("http://localhost:%s/cache/%s/update",
		extractPort(svc.cfg.HTTPEndpoint), name)
	log.Printf("Notifying web: %s", url)
	// Best-effort HTTP GET - errors are logged but not fatal
	resp, err := httpGet(url)
	if err != nil {
		log.Printf("Error notifying web for %s: %v", name, err)
		return
	}
	if resp != 200 {
		log.Printf("Web update for %s returned status %d", name, resp)
	}
}

// extractPort extracts the port from a host:port string.
func extractPort(endpoint string) string {
	_, port, err := parseHostPort(endpoint)
	if err != nil {
		return "8087"
	}
	return port
}

// parseHostPort splits host:port. Minimal wrapper for clarity.
func parseHostPort(hostport string) (string, string, error) {
	for i := len(hostport) - 1; i >= 0; i-- {
		if hostport[i] == ':' {
			return hostport[:i], hostport[i+1:], nil
		}
	}
	return "", "", fmt.Errorf("no colon in %q", hostport)
}

// httpGet performs a simple HTTP GET and returns the status code.
func httpGet(targetURL string) (int, error) {
	resp, err := http.Get(targetURL)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()
	return resp.StatusCode, nil
}
