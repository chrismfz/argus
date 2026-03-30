package slack

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"argus/internal/alerter"
)

type Backend struct {
	webhook     string
	minSeverity alerter.Severity
	httpClient  *http.Client
}

func New(webhook string, minSeverity alerter.Severity) *Backend {
	return &Backend{
		webhook:     webhook,
		minSeverity: minSeverity,
		httpClient:  &http.Client{Timeout: 10 * time.Second},
	}
}

func (b *Backend) Name() string { return "slack" }

func (b *Backend) Send(ctx context.Context, e alerter.Event) error {
	if b.webhook == "" {
		return fmt.Errorf("slack webhook not configured")
	}

	color := colorFor(e.Severity)
	tagsText := ""
	for k, v := range e.Tags {
		tagsText += fmt.Sprintf("• *%s*: %s\n", k, v)
	}

	payload := map[string]interface{}{
		"attachments": []map[string]interface{}{
			{
				"color":      color,
				"title":      fmt.Sprintf("[%s] %s", severityLabel(e.Severity), e.Title),
				"text":       e.Body,
				"footer":     fmt.Sprintf("argus · %s · %s", e.Source, e.Time.UTC().Format("2006-01-02 15:04:05 UTC")),
				"fields":     buildFields(e.Tags),
				"mrkdwn_in":  []string{"text"},
			},
		},
	}

	_ = tagsText // tags are included via fields

	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("slack marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.webhook, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("slack request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("slack send: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func colorFor(s alerter.Severity) string {
	switch s {
	case alerter.SeverityCritical:
		return "#f38ba8" // red
	case alerter.SeverityWarning:
		return "#fab387" // orange
	default:
		return "#89b4fa" // blue
	}
}

func severityLabel(s alerter.Severity) string {
	switch s {
	case alerter.SeverityCritical:
		return "🔴 CRITICAL"
	case alerter.SeverityWarning:
		return "🟠 WARNING"
	default:
		return "🔵 INFO"
	}
}

func buildFields(tags map[string]string) []map[string]interface{} {
	var fields []map[string]interface{}
	for k, v := range tags {
		fields = append(fields, map[string]interface{}{
			"title": k,
			"value": v,
			"short": true,
		})
	}
	return fields
}
