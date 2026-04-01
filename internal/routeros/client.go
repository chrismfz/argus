package routeros

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// Config is the RouterOS REST API configuration.
type Config struct {
	Enabled        bool   `yaml:"enabled"`
	Address        string `yaml:"address"`         // "http://84.54.49.1" or "https://84.54.49.1"
	Username       string `yaml:"username"`
	Password       string `yaml:"password"`
	InsecureTLS    bool   `yaml:"insecure_tls"`    // accept self-signed certs
	TimeoutSeconds int    `yaml:"timeout_seconds"` // default 10
}

func (c Config) timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Client is a RouterOS REST API client.
// All methods are safe for concurrent use — each call creates its own HTTP request.
type Client struct {
	cfg  Config
	http *http.Client
}

// NewClient creates a REST Client from config.
func NewClient(cfg Config) *Client {
	tr := &http.Transport{}
	if cfg.InsecureTLS {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec — user opt-in
	}
	return &Client{
		cfg:  cfg,
		http: &http.Client{Timeout: cfg.timeout(), Transport: tr},
	}
}

// Dial creates a Client and verifies connectivity.
func Dial(cfg Config) (*Client, error) {
	c := NewClient(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), cfg.timeout())
	defer cancel()
	if _, err := c.SystemIdentity(ctx); err != nil {
		return nil, fmt.Errorf("routeros REST %s: %w", cfg.Address, err)
	}
	return c, nil
}

// get calls GET /rest/<path>?<query> and JSON-decodes the response into dest.
func (c *Client) get(ctx context.Context, path string, query url.Values, dest interface{}) error {
	u := c.cfg.Address + "/rest/" + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("GET /rest/%s: %w", path, err)
	}
	defer resp.Body.Close()

	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusUnauthorized:
		return fmt.Errorf("routeros REST: unauthorized — check credentials")
	default:
		return fmt.Errorf("routeros REST GET /rest/%s: HTTP %d", path, resp.StatusCode)
	}

	if err := json.NewDecoder(resp.Body).Decode(dest); err != nil {
		return fmt.Errorf("routeros REST decode /rest/%s: %w", path, err)
	}
	return nil
}

// post calls POST /rest/<path> with a JSON body and decodes the response.
func (c *Client) post(ctx context.Context, path string, body interface{}, dest interface{}) error {
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			return err
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.Address+"/rest/"+path, &buf)
	if err != nil {
		return err
	}
	req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST /rest/%s: %w", path, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("routeros REST POST /rest/%s: HTTP %d", path, resp.StatusCode)
	}
	if dest != nil {
		return json.NewDecoder(resp.Body).Decode(dest)
	}
	return nil
}


// postSlow is like post but uses a longer HTTP timeout for slow commands
// like traceroute that can take 20-30s to complete.
func (c *Client) postSlow(ctx context.Context, path string, body interface{}, dest interface{}) error {
    slowClient := &http.Client{
        Timeout:   25 * time.Second,
        Transport: c.http.Transport,
    }

    var buf bytes.Buffer
    if body != nil {
        if err := json.NewEncoder(&buf).Encode(body); err != nil {
            return err
        }
    }
    req, err := http.NewRequestWithContext(ctx, http.MethodPost,
        c.cfg.Address+"/rest/"+path, &buf)
    if err != nil {
        return err
    }
    req.SetBasicAuth(c.cfg.Username, c.cfg.Password)
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Accept", "application/json")

    resp, err := slowClient.Do(req)
    if err != nil {
        return fmt.Errorf("POST /rest/%s: %w", path, err)
    }
    defer resp.Body.Close()

    if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
        return fmt.Errorf("routeros REST POST /rest/%s: HTTP %d", path, resp.StatusCode)
    }
    if dest != nil {
        return json.NewDecoder(resp.Body).Decode(dest)
    }
    return nil
}
