package main

import (
	"flag"
	"log"
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

	updateService := irrd.NewWhoisCacheUpdateService(cfg)
	if err := updateService.Start(); err != nil {
		log.Fatalf("Update service failed: %v", err)
	}
}
