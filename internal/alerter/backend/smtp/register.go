package smtp

import (
	"encoding/json"
	"fmt"

	"argus/internal/alerter"
)

func init() {
	alerter.RegisterFactory("smtp", func(c alerter.Contact) (alerter.Backend, error) {
		var cfg alerter.SMTPConfig
		if err := json.Unmarshal([]byte(c.Config), &cfg); err != nil {
			return nil, fmt.Errorf("parse smtp config: %w", err)
		}
		if cfg.Host == "" {
			return nil, fmt.Errorf("smtp host is empty")
		}
		if cfg.Port == 0 {
			cfg.Port = 587
		}
		if len(cfg.To) == 0 {
			return nil, fmt.Errorf("smtp: no recipients")
		}
		return New(cfg.Host, cfg.Port, cfg.Username, cfg.Password, cfg.From, cfg.To, cfg.TLS), nil
	})
}
