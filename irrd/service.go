package irrd

import (
	"fmt"
	"log"
	"sort"
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
	sort.Strings(keys)
	return keys
}

func (d *directMap) Items() []MapEntry {
	keys := d.Keys()
	entries := make([]MapEntry, 0, len(keys))
	for _, k := range keys {
		entries = append(entries, MapEntry{Key: k, Value: d.m[k].Slice()})
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

// NewWhoisCacheService creates a service with caches for all configured upstreams.
// Caches start empty; call StartUpdateLoop to populate them.
func NewWhoisCacheService(cfg *Config) *WhoisCacheService {
	svc := &WhoisCacheService{
		Caches: make(map[string]*WhoisCache),
		cfg:    cfg,
	}
	for _, up := range cfg.NRTMv3Upstreams {
		svc.Caches[up.Name] = NewNRTMv3Cache(up, cfg)
	}
	for _, up := range cfg.NRTMv4Upstreams {
		svc.Caches[up.Name] = NewNRTMv4Cache(up, cfg)
	}
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

// StartUpdateLoop runs the initial update of all caches in the service,
// then enters an infinite loop updating each cache at the configured interval.
// Update errors are logged but never fatal — the server stays up and retries
// on the next interval. This should be called in a goroutine.
func (svc *WhoisCacheService) StartUpdateLoop() {
	// Initial update
	for _, cache := range svc.Caches {
		log.Printf("Initial update: %s", cache.Name)
		if err := cache.Update(); err != nil {
			log.Printf("Error in initial update of %s: %v", cache.Name, err)
		}
	}
	log.Printf("Initial update pass complete")

	// Update loop
	for {
		time.Sleep(time.Duration(svc.cfg.WhoisUpdateInterval) * time.Second)
		for _, cache := range svc.Caches {
			log.Printf("Updating cache: %s", cache.Name)
			if err := cache.Update(); err != nil {
				log.Printf("Error updating cache %s: %v", cache.Name, err)
			}
		}
	}
}
