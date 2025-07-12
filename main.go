package main

import (
	"fmt"
	"log"
	"os"
)

var debug bool

func dlog(msg string, args ...interface{}) {
	if debug {
		log.Printf("[DEBUG] "+msg, args...)
	}
}

func main() {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}
	cfg, err := LoadConfig(configPath)
	if err != nil {
		log.Fatalf("Error loading config: %v", err)
	}
	debug = cfg.Debug

	dlog("ClickHouse Host: %s", cfg.ClickHouse.Host)
	dlog("GeoIP ASN DB: %s", cfg.GeoIP.ASNDB)
	fmt.Println("Config loaded successfully.")
}
