package main

import (
	"bufio"
	"context"
	"os"
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

		line = trimLine(line)
		if line == "" {
			continue
		}

		dlog("Read: %s", line)
		rec, err := ParseAndEnrich(line, geo, bgp, dns, cfg.Timezone)
		if err != nil {
			dlog("Skip line: %v", err)
			continue
		}

		if err := inserter.InsertFlow(context.Background(), rec); err != nil {
			dlog("Insert error: %v", err)
		} else {
			dlog("Inserted flow at %s", rec.TimestampStart)
		}
	}
}

func trimLine(s string) string {
	return string([]byte(s)[0:len(s)-1])
}
