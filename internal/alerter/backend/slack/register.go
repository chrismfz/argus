package slack

import (
	"encoding/json"
	"fmt"

	"argus/internal/alerter"
)

func init() {
	alerter.RegisterFactory("slack", func(c alerter.Contact) (alerter.Backend, error) {
		var cfg alerter.SlackConfig
		if err := json.Unmarshal([]byte(c.Config), &cfg); err != nil {
			return nil, fmt.Errorf("parse slack config: %w", err)
		}
		if cfg.Webhook == "" {
			return nil, fmt.Errorf("slack webhook is empty")
		}
		return New(cfg.Webhook, c.MinSeverity), nil
	})
}
