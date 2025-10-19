package cfmapi

import (
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

func (c *Client) http() *http.Client {
	if c.HTTP != nil { return c.HTTP }
	return &http.Client{ Timeout: 10 * time.Second }
}

func (c *Client) doPOST(path string, form url.Values) ([]byte, error) {
	u := strings.TrimRight(c.BaseURL, "/") + path
	req, _ := http.NewRequest("POST", u, strings.NewReader(form.Encode()))
	req.Header.Set("Token", c.Token)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Agent-Version", "FlowEnricher-Go")

	resp, err := c.http().Do(req)
	if err != nil { return nil, err }
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.StatusCode >= 300 {
		return b, fmt.Errorf("http %d: %s", resp.StatusCode, string(b))
	}
	return b, nil
}

// ReportBlock posts a blacklisted IP with an optional TTL (seconds). Description is shown in CFM.
func (c *Client) ReportBlock(ip, description string, ttlSec int) error {
	p := url.Values{
		"ip":          {ip},
		"comment":     {description},
		"description": {description},
		"timestamp":   {time.Now().Format(time.RFC3339)},
	}
	if ttlSec > 0 {
		p.Set("ttl", fmt.Sprintf("%d", ttlSec))
	}
	_, err := c.doPOST("/api/blocklist/report", p)
	return err
}

func (c *Client) ReportUnblock(ip, source, why string) error {
	p := url.Values{
		"ip":     {ip},
		"source": {source},
		"reason": {why},
	}
	_, err := c.doPOST("/api/blocklist/unblock", p)
	return err
}
