package main

import (
	"flag"
	"log"
	"net/http"
	"os"

	"github.com/liam-dev-c/gotinyirrdbcache/irrd"
)

func main() {
	configPath := flag.String("config", "config.json", "path to config file")
	flag.Parse()

	cfg, err := irrd.LoadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := os.MkdirAll(cfg.CacheDataDirectory, 0o755); err != nil {
		log.Fatalf("Failed to create data directory: %v", err)
	}

	service := irrd.NewWhoisCacheService(cfg)

	// Run the update loop in the background
	go service.StartUpdateLoop()

	server := irrd.NewServer(service)
	log.Printf("Listening on http://%s/", cfg.HTTPEndpoint)
	if err := http.ListenAndServe(cfg.HTTPEndpoint, server); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}
