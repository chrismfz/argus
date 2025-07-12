package main

import (
	"bufio"
	"context"
	"os"
	"strings"
	"time"
)

func TailFileAndProcess(path string, geo *GeoIP, bgp *BGPTable, dns *DNSResolver, cfg *Config, inserter *ClickHouseInserter) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Seek to end
	file.Seek(0, os.SEEK_END)

	reader := bufio.NewReader(file)

	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		dlog("Read: %s", line)

		rec, err := ParseAndEnrich(line, geo, bgp, dns, cfg.Timezone)
		if err != nil {
			dlog("Skip line: %v", err)
			continue
		}

		Stats.Parsed++
		if rec.SrcHostPTR != "" {
			Stats.PTRLookups++
		}
		if rec.DstHostPTR != "" {
			Stats.PTRLookups++
		}

		if err := inserter.InsertFlow(context.Background(), rec); err != nil {
			dlog("Insert error: %v", err)
		} else {
			Stats.Inserted++
			dlog("Inserted flow at %s", rec.TimestampStart)
		}
	}
}
