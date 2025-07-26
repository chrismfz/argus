package main

import (
	"context"
	"log"
	"strings"
	"time"
	"flowenricher/config"
        "flowenricher/enrich"
	"github.com/segmentio/kafka-go"
	"github.com/yl2chen/cidranger"
)

func StartKafkaConsumer(ctx context.Context, cfg *config.Config, geo *enrich.GeoIP, ranger cidranger.Ranger, dns *enrich.DNSResolver, batcher *InsertFlowBatcher) error {
	r := kafka.NewReader(kafka.ReaderConfig{
		Brokers:     cfg.Kafka.Brokers,
		Topic:       cfg.Kafka.Topic,
		GroupID:     cfg.Kafka.GroupID,
		StartOffset: kafka.LastOffset, // πάντα από real-time
		MinBytes:    1e3,
		MaxBytes:    10e6,
	})
	defer r.Close()

	dlog("Kafka consumer started on topic %s", cfg.Kafka.Topic)

	for {
		m, err := r.ReadMessage(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return nil // graceful exit
			}
			log.Printf("Kafka read error: %v", err)
			continue
		}

		line := strings.TrimSpace(string(m.Value))
		if line == "" {
			continue
		}

		start := time.Now()
		rec, err := ParseAndEnrich(line, geo, dns, cfg.Timezone)
		dlog("Enrichment time: %v", time.Since(start))
		if err != nil {
			dlog("Parse failed: %v", err)
			continue
		}


		batcher.Add(rec)
	}
}
