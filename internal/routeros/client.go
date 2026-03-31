package routeros

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"sync"
	"time"

	ros "github.com/go-routeros/routeros/v3"
)

// Config is the RouterOS API connection configuration.
// It maps directly to the RouterOSConfig yaml struct in config.go.
type Config struct {
	Enabled        bool          `yaml:"enabled"`
	Address        string        `yaml:"address"`         // host:port, e.g. 84.54.49.1:8728
	Username       string        `yaml:"username"`
	Password       string        `yaml:"password"`
	UseTLS         bool          `yaml:"use_tls"`         // use port 8729 + TLS
	InsecureTLS    bool          `yaml:"insecure_tls"`    // skip cert verification (self-signed)
	TimeoutSeconds int           `yaml:"timeout_seconds"` // default 10
}

func (c Config) timeout() time.Duration {
	if c.TimeoutSeconds <= 0 {
		return 10 * time.Second
	}
	return time.Duration(c.TimeoutSeconds) * time.Second
}

// Client wraps the go-routeros connection with automatic reconnect.
// All public methods are safe for concurrent use.
type Client struct {
	cfg  Config
	mu   sync.Mutex
	conn *ros.Client
}

// NewClient creates a Client. Call Connect() before using query methods,
// or call Dial() which connects immediately.
func NewClient(cfg Config) *Client {
	return &Client{cfg: cfg}
}

// Dial creates a Client and establishes the connection immediately.
func Dial(cfg Config) (*Client, error) {
	c := NewClient(cfg)
	if err := c.Connect(); err != nil {
		return nil, err
	}
	return c, nil
}

// Connect (re)establishes the RouterOS API connection.
func (c *Client) Connect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}

	var (
		conn *ros.Client
		err  error
	)

	if c.cfg.UseTLS {
		tlsCfg := &tls.Config{
			InsecureSkipVerify: c.cfg.InsecureTLS, //nolint:gosec — user opt-in
		}
		conn, err = ros.DialTLS(c.cfg.Address, c.cfg.Username, c.cfg.Password, tlsCfg)
	} else {
		conn, err = ros.Dial(c.cfg.Address, c.cfg.Username, c.cfg.Password)
	}
	if err != nil {
		return fmt.Errorf("routeros dial %s: %w", c.cfg.Address, err)
	}
	conn.Queue = 100 // default is 1; raises throughput for bulk queries
	c.conn = conn
	log.Printf("[RouterOS] connected to %s", c.cfg.Address)
	return nil
}

// Close terminates the connection.
func (c *Client) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		c.conn.Close()
		c.conn = nil
	}
}

// run executes a RouterOS API command and returns the raw reply sentences.
// On a closed-connection error it reconnects once and retries.
func (c *Client) run(ctx context.Context, command string, args ...string) (*ros.Reply, error) {
	words := append([]string{command}, args...)

	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()

	if conn == nil {
		if err := c.Connect(); err != nil {
			return nil, err
		}
		c.mu.Lock()
		conn = c.conn
		c.mu.Unlock()
	}

	reply, err := conn.RunArgs(words)
	if err != nil {
		// Connection may have dropped — try once to reconnect
		log.Printf("[RouterOS] command error (%s): %v — reconnecting", command, err)
		if rerr := c.Connect(); rerr != nil {
			return nil, fmt.Errorf("reconnect failed: %w", rerr)
		}
		c.mu.Lock()
		conn = c.conn
		c.mu.Unlock()
		reply, err = conn.RunArgs(words)
		if err != nil {
			return nil, fmt.Errorf("routeros %s: %w", command, err)
		}
	}
	return reply, nil
}

// Ping checks connectivity by fetching the router identity.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.run(ctx, "/system/identity/print")
	return err
}
