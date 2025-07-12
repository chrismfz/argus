package main

import (
	"bufio"
	"context"
	"os"
	"strings"
	"time"
)

func TailFileAndProcess(ctx context.Context, path string, geo *GeoIP, bgp *BGPTable, dns *DNSResolver, cfg *Config, inserter *ClickHouseInserter) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	// Seek to end
	file.Seek(0, os.SEEK_END)
	reader := bufio.NewReader(file)

	Stats.StartTime = time.Now()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
			line, err := reader.ReadString('\n')
			if err != nil {
				time.Sleep(500 * time.Millisecond)
				continue
			}

			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}

			if showFlows {
				dlog("Read: %s", line)
			}

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

			if Stats.Parsed == 1 {
				// Δηλώνει πότε ξεκίνησε πραγματικά ο εμπλουτισμός
				Stats.EnrichDone = time.Now()
			}

			if err := inserter.InsertFlow(context.Background(), rec); err != nil {
				dlog("Insert error: %v", err)
			} else {
				Stats.Inserted++
				if showFlows {
					dlog("Inserted flow at %s", rec.TimestampStart)
				}
			}
		}
	}
}
