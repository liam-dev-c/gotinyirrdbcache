package irrd

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	cacheReady = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "irrd_cache_ready",
		Help: "Whether a cache is ready (1) or not (0).",
	}, []string{"cache"})

	cacheSerial = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "irrd_cache_serial",
		Help: "Current serial number of a cache.",
	}, []string{"cache"})

	cacheMacroCount = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "irrd_cache_macros_total",
		Help: "Number of macros in a cache.",
	}, []string{"cache"})

	cachePrefix4Count = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "irrd_cache_prefix4_origins_total",
		Help: "Number of origin ASNs with IPv4 prefixes in a cache.",
	}, []string{"cache"})

	cachePrefix6Count = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "irrd_cache_prefix6_origins_total",
		Help: "Number of origin ASNs with IPv6 prefixes in a cache.",
	}, []string{"cache"})

	httpRequestsTotal = prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "irrd_http_requests_total",
		Help: "Total HTTP requests by method and path.",
	}, []string{"method", "path", "status"})
)

func init() {
	prometheus.MustRegister(cacheReady, cacheSerial, cacheMacroCount,
		cachePrefix4Count, cachePrefix6Count, httpRequestsTotal)
}

// Server is the HTTP server for the IRRD cache API.
type Server struct {
	Service *WhoisCacheService
	mux     *http.ServeMux
}

// NewServer creates a new HTTP server with all routes registered.
func NewServer(service *WhoisCacheService) *Server {
	s := &Server{Service: service}
	s.mux = http.NewServeMux()
	s.registerRoutes()
	return s
}

// ServeHTTP implements http.Handler.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("GET /", s.handleIndex)
	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.Handle("GET /metrics", promhttp.Handler())
	s.mux.HandleFunc("GET /cache/{cache}/macros/lookup/{key}", s.withCache(s.handleLookupMacros))
	s.mux.HandleFunc("GET /cache/{cache}/macros/list", s.withCache(s.handleListMacros))
	s.mux.HandleFunc("GET /cache/{cache}/prefixes/4/lookup/{key}", s.withCache(s.handleLookupPrefix4))
	s.mux.HandleFunc("GET /cache/{cache}/prefixes/4/list", s.withCache(s.handleListPrefix4))
	s.mux.HandleFunc("GET /cache/{cache}/prefixes/6/lookup/{key}", s.withCache(s.handleLookupPrefix6))
	s.mux.HandleFunc("GET /cache/{cache}/prefixes/6/list", s.withCache(s.handleListPrefix6))
	s.mux.HandleFunc("GET /cache/{cache}/status", s.withCache(s.handleStatus))
	s.mux.HandleFunc("GET /cache/{cache}/update", s.handleUpdate)
	s.mux.HandleFunc("GET /cache/{cache}/dump", s.withCache(s.handleDump))
}

// withCache is middleware that resolves the cache name and provides
// the CacheStateProvider to the handler.
func (s *Server) withCache(handler func(http.ResponseWriter, *http.Request, CacheStateProvider)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cacheName := r.PathValue("cache")
		state, err := s.Service.GetCacheState(cacheName)
		if err != nil {
			if errors.Is(err, ErrCacheNotReady) {
				http.Error(w, "Cache Not Ready", http.StatusServiceUnavailable)
				return
			}
			if strings.Contains(err.Error(), "no such cache") {
				http.Error(w, "No Such Cache", http.StatusNotFound)
				return
			}
			http.Error(w, "Cache Init Error", http.StatusInternalServerError)
			return
		}
		handler(w, r, state)
	}
}

// handleIndex returns API documentation.
func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	cacheNames := make([]string, 0, len(s.Service.Caches))
	for name := range s.Service.Caches {
		cacheNames = append(cacheNames, name)
	}
	sort.Strings(cacheNames)

	routes := []struct {
		Path string
		Doc  string
	}{
		{"/", "This page"},
		{"/healthz", "Health check"},
		{"/metrics", "Prometheus metrics"},
		{"/cache/{cache}/macros/lookup/{key}", "Lookup macro by name"},
		{"/cache/{cache}/macros/list", "List macro names"},
		{"/cache/{cache}/prefixes/4/lookup/{key}", "Lookup ipv4 prefixes by ASN"},
		{"/cache/{cache}/prefixes/4/list", "List ASNs with ipv4 prefixes"},
		{"/cache/{cache}/prefixes/6/lookup/{key}", "Lookup ipv6 prefixes by ASN"},
		{"/cache/{cache}/prefixes/6/list", "List ASNs with ipv6 prefixes"},
		{"/cache/{cache}/status", "Return status of cache"},
		{"/cache/{cache}/update", "Reloads the cache"},
		{"/cache/{cache}/dump", "Dump all data for named cache"},
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte("<h1>Whois Cache</h1>\n"))
	w.Write([]byte("<p>Loaded caches: <b>" + strings.Join(cacheNames, ", ") + ", ALL</b> (combined logical OR)</p>\n"))
	w.Write([]byte("<table border=1>\n"))
	for _, route := range routes {
		w.Write([]byte("<tr><td><pre>GET " + route.Path + "</pre></td><td><pre>" + route.Doc + "</pre></td></tr>\n"))
	}
	w.Write([]byte("</table>\n"))
}

// handleLookupMacros looks up a macro by name.
func (s *Server) handleLookupMacros(w http.ResponseWriter, r *http.Request, cache CacheStateProvider) {
	key := r.PathValue("key")
	items, ok := cache.GetMacros().Lookup(key)
	if !ok {
		writeJSON404(w)
		return
	}
	writeJSON200(w, items)
}

// handleListMacros lists all macro names.
func (s *Server) handleListMacros(w http.ResponseWriter, r *http.Request, cache CacheStateProvider) {
	writeJSON200(w, cache.GetMacros().Keys())
}

// handleLookupPrefix4 looks up IPv4 prefixes by ASN.
func (s *Server) handleLookupPrefix4(w http.ResponseWriter, r *http.Request, cache CacheStateProvider) {
	key := r.PathValue("key")
	items, ok := cache.GetPrefix4().Lookup(key)
	if !ok {
		writeJSON404(w)
		return
	}
	writeJSON200(w, items)
}

// handleListPrefix4 lists ASNs with IPv4 prefixes.
func (s *Server) handleListPrefix4(w http.ResponseWriter, r *http.Request, cache CacheStateProvider) {
	writeJSON200(w, cache.GetPrefix4().Keys())
}

// handleLookupPrefix6 looks up IPv6 prefixes by ASN.
func (s *Server) handleLookupPrefix6(w http.ResponseWriter, r *http.Request, cache CacheStateProvider) {
	key := r.PathValue("key")
	items, ok := cache.GetPrefix6().Lookup(key)
	if !ok {
		writeJSON404(w)
		return
	}
	writeJSON200(w, items)
}

// handleListPrefix6 lists ASNs with IPv6 prefixes.
func (s *Server) handleListPrefix6(w http.ResponseWriter, r *http.Request, cache CacheStateProvider) {
	writeJSON200(w, cache.GetPrefix6().Keys())
}

// handleStatus returns cache serial and update timestamp.
func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request, cache CacheStateProvider) {
	writeJSON200(w, map[string]string{
		"serial":     cache.GetSerial(),
		"updated_at": cache.GetUpdatedAt(),
	})
}

// handleUpdate triggers a cache reload from disk.
func (s *Server) handleUpdate(w http.ResponseWriter, r *http.Request) {
	cacheName := r.PathValue("cache")
	if err := s.Service.UpdateCache(cacheName); err != nil {
		if strings.Contains(err.Error(), "no such cache") {
			http.Error(w, "No Such Cache", http.StatusNotFound)
			return
		}
		if errors.Is(err, ErrCacheNotReady) {
			http.Error(w, "Cache Not Ready", http.StatusServiceUnavailable)
			return
		}
		log.Printf("Error updating cache %s: %v", cacheName, err)
		http.Error(w, "Something went wrong", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// handleDump exports the entire cache as JSON.
func (s *Server) handleDump(w http.ResponseWriter, r *http.Request, cache CacheStateProvider) {
	macros := make(map[string][]string)
	for _, entry := range cache.GetMacros().Items() {
		macros[entry.Key] = entry.Value
	}
	prefix4 := make(map[string][]string)
	for _, entry := range cache.GetPrefix4().Items() {
		prefix4[entry.Key] = entry.Value
	}
	prefix6 := make(map[string][]string)
	for _, entry := range cache.GetPrefix6().Items() {
		prefix6[entry.Key] = entry.Value
	}

	writeJSON200(w, map[string]interface{}{
		"serial":  cache.GetSerial(),
		"macros":  macros,
		"prefix4": prefix4,
		"prefix6": prefix6,
	})
}

// handleHealth returns 200 if any cache is ready, 503 otherwise.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.updateMetrics()

	anyReady := false
	statuses := make(map[string]string)
	for name, cache := range s.Service.Caches {
		if cache.Ready {
			anyReady = true
			statuses[name] = "ready"
		} else {
			statuses[name] = "not_ready"
		}
	}

	status := http.StatusOK
	if !anyReady {
		status = http.StatusServiceUnavailable
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status": status == http.StatusOK,
		"caches": statuses,
	})
}

// updateMetrics refreshes Prometheus gauges from current cache state.
func (s *Server) updateMetrics() {
	for name, cache := range s.Service.Caches {
		if cache.Ready {
			cacheReady.WithLabelValues(name).Set(1)
			cacheMacroCount.WithLabelValues(name).Set(float64(len(cache.State.Macros)))
			cachePrefix4Count.WithLabelValues(name).Set(float64(len(cache.State.Prefix4)))
			cachePrefix6Count.WithLabelValues(name).Set(float64(len(cache.State.Prefix6)))
			if serial, err := parseFloat(cache.State.Serial); err == nil {
				cacheSerial.WithLabelValues(name).Set(serial)
			}
		} else {
			cacheReady.WithLabelValues(name).Set(0)
		}
	}
}

// parseFloat is a helper to convert serial strings to float64 for Prometheus.
func parseFloat(s string) (float64, error) {
	var f float64
	_, err := fmt.Sscanf(s, "%f", &f)
	return f, err
}

func writeJSON200(w http.ResponseWriter, data interface{}) {
	resp := map[string]interface{}{
		"status": "200 OK",
		"data":   data,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

func writeJSON404(w http.ResponseWriter) {
	resp := map[string]string{"status": "404 NOT FOUND"}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(resp)
}
