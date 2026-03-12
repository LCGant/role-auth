package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/LCGant/role-auth/internal/config"
)

type Client struct {
	baseURL       string
	internalToken string
	spoolDir      string
	timeout       time.Duration
	queue         chan Event
	httpClient    *http.Client
	logger        *slog.Logger
	once          sync.Once
}

type Event struct {
	Source    string         `json:"source"`
	EventType string         `json:"event_type"`
	UserID    *int64         `json:"user_id,omitempty"`
	Provider  string         `json:"provider,omitempty"`
	IP        string         `json:"ip,omitempty"`
	UserAgent string         `json:"user_agent,omitempty"`
	Success   bool           `json:"success"`
	Metadata  map[string]any `json:"metadata,omitempty"`
	CreatedAt time.Time      `json:"created_at"`
}

func NewClient(cfg config.Config) *Client {
	if strings.TrimSpace(cfg.Audit.BaseURL) == "" || strings.TrimSpace(cfg.Audit.InternalToken) == "" {
		return nil
	}
	return &Client{
		baseURL:       strings.TrimRight(cfg.Audit.BaseURL, "/"),
		internalToken: cfg.Audit.InternalToken,
		spoolDir:      strings.TrimSpace(cfg.Audit.SpoolDir),
		timeout:       cfg.Audit.Timeout,
		queue:         make(chan Event, 128),
		httpClient:    &http.Client{Timeout: cfg.Audit.Timeout},
		logger:        slog.Default(),
	}
}

func (c *Client) Record(ctx context.Context, event Event) error {
	if c == nil {
		return nil
	}
	c.once.Do(func() {
		go c.run()
	})
	select {
	case c.queue <- event:
		return nil
	default:
		if err := c.spool(event); err != nil {
			return fmt.Errorf("audit queue full and spool failed: %w", err)
		}
		return nil
	}
}

func (c *Client) run() {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case event := <-c.queue:
			c.deliverOrSpool(event)
		case <-ticker.C:
			c.flushSpool()
		}
	}
}

func (c *Client) deliverOrSpool(event Event) {
	if err := c.sendWithRetry(event); err != nil {
		if spoolErr := c.spool(event); spoolErr != nil {
			c.logger.Warn("auth audit forward dropped after spool failure", "event", event.EventType, "error", err, "spool_error", spoolErr)
		}
	}
}

func (c *Client) sendWithRetry(event Event) error {
	const maxAttempts = 3
	const baseBackoff = 100 * time.Millisecond
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if err := c.send(event); err == nil {
			return nil
		} else if attempt == maxAttempts {
			c.logger.Warn("auth audit forward failed after retries; spooling", "event", event.EventType, "attempts", attempt, "error", err)
			return err
		} else {
			c.logger.Warn("auth audit forward failed; retrying", "event", event.EventType, "attempt", attempt, "error", err)
			time.Sleep(time.Duration(attempt) * baseBackoff)
		}
	}
	return nil
}

func (c *Client) send(event Event) error {
	timeout := c.timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/internal/events", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Internal-Token", c.internalToken)

	client := c.httpClient
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return fmt.Errorf("audit service returned %d", resp.StatusCode)
	}
	return nil
}

func (c *Client) spool(event Event) error {
	if strings.TrimSpace(c.spoolDir) == "" {
		return fmt.Errorf("audit spool dir not configured")
	}
	if err := os.MkdirAll(c.spoolDir, 0o700); err != nil {
		return err
	}
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%d-%s.json", time.Now().UTC().UnixNano(), sanitizeName(event.EventType))
	return os.WriteFile(filepath.Join(c.spoolDir, name), payload, 0o600)
}

func (c *Client) flushSpool() {
	if strings.TrimSpace(c.spoolDir) == "" {
		return
	}
	entries, err := os.ReadDir(c.spoolDir)
	if err != nil {
		if !os.IsNotExist(err) {
			c.logger.Warn("auth audit spool read failed", "error", err)
		}
		return
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name() < entries[j].Name()
	})
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(c.spoolDir, entry.Name())
		payload, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var event Event
		if err := json.Unmarshal(payload, &event); err != nil {
			_ = os.Remove(path)
			continue
		}
		if err := c.sendWithRetry(event); err != nil {
			break
		}
		_ = os.Remove(path)
	}
}

func sanitizeName(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return "event"
	}
	var b strings.Builder
	for _, r := range v {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			continue
		}
		b.WriteByte('-')
	}
	return strings.Trim(b.String(), "-")
}
