package session

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/ginkida/agent-runner/internal/auth"
	"github.com/ginkida/agent-runner/internal/netutil"
	"github.com/ginkida/agent-runner/internal/resilience"
)

// StatusNotifier sends session status callbacks to Laravel.
// Notifications are fire-and-forget — they never block the agent loop.
// Goroutines are bounded by a semaphore to prevent resource exhaustion.
type StatusNotifier struct {
	baseURL    string
	hmacSecret string
	httpClient *http.Client
	sem        chan struct{} // bounds concurrent notification goroutines
	dropped    atomic.Uint64
}

// StatusPayload is the JSON body sent to Laravel on status transitions.
type StatusPayload struct {
	SessionID  string `json:"session_id"`
	ClientID   string `json:"client_id"`
	Status     string `json:"status"`
	Error      string `json:"error,omitempty"`
	Output     string `json:"output,omitempty"`
	Turns      int    `json:"turns,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

// NewStatusNotifier creates a notifier that calls back to Laravel.
func NewStatusNotifier(baseURL, hmacSecret string, timeoutSec int) *StatusNotifier {
	timeout := 10 * time.Second
	if timeoutSec > 0 {
		timeout = time.Duration(timeoutSec) * time.Second
	}
	return &StatusNotifier{
		baseURL:    strings.TrimSuffix(baseURL, "/"),
		hmacSecret: hmacSecret,
		httpClient: &http.Client{Timeout: timeout, Transport: netutil.SafeTransport()},
		sem:        make(chan struct{}, 32), // max 32 concurrent notifications
	}
}

// Notify sends a status update to Laravel asynchronously.
// It never blocks and logs errors instead of returning them.
// Goroutines are bounded by a semaphore — if full, the notification is dropped.
func (n *StatusNotifier) Notify(ctx context.Context, p StatusPayload) {
	select {
	case n.sem <- struct{}{}:
	default:
		n.dropped.Add(1)
		log.Printf("[notifier] dropping notification status=%s session=%s: semaphore full (total dropped: %d)", p.Status, p.SessionID, n.dropped.Load())
		return
	}
	go func() {
		defer func() { <-n.sem }()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("[notifier] panic recovered status=%s session=%s: %v", p.Status, p.SessionID, r)
			}
		}()

		notifyCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		if err := n.doNotify(notifyCtx, p); err != nil {
			log.Printf("[notifier] failed to notify status=%s session=%s: %v", p.Status, p.SessionID, err)
		}
	}()
}

// NotifyWithURL sends a status update using a per-session callback URL override.
// If overrideURL is empty, falls back to the default base URL.
// Shares the same httpClient and semaphore as the original notifier.
func (n *StatusNotifier) NotifyWithURL(ctx context.Context, overrideURL string, p StatusPayload) {
	if overrideURL == "" {
		n.Notify(ctx, p)
		return
	}
	override := &StatusNotifier{
		baseURL:    strings.TrimSuffix(overrideURL, "/"),
		hmacSecret: n.hmacSecret,
		httpClient: n.httpClient,
		sem:        n.sem,
	}
	override.Notify(ctx, p)
}

// DroppedCount returns the total number of dropped notifications.
func (n *StatusNotifier) DroppedCount() uint64 {
	return n.dropped.Load()
}

func (n *StatusNotifier) doNotify(ctx context.Context, p StatusPayload) error {
	body, err := json.Marshal(p)
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}

	url := fmt.Sprintf("%s/sessions/%s/status", n.baseURL, p.SessionID)

	return resilience.RetryWithBackoff(ctx, resilience.RetryConfig{
		MaxRetries:  3,
		BaseDelay:   time.Second,
		MaxDelay:    5 * time.Second,
		IsRetryable: isNotifyRetryable,
	}, func() error {
		req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(body))
		if err != nil {
			return fmt.Errorf("request: %w", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Session-ID", p.SessionID)

		if n.hmacSecret != "" {
			sig, ts := auth.SignRequest(n.hmacSecret, body)
			req.Header.Set("X-Signature", sig)
			req.Header.Set("X-Timestamp", ts)
		}

		resp, err := n.httpClient.Do(req)
		if err != nil {
			return err // network error → retryable
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body) // drain body

		if resp.StatusCode >= 500 {
			return fmt.Errorf("status callback returned %d", resp.StatusCode)
		}
		// 4xx = not retryable, but we don't fail the session for it
		return nil
	})
}

func isNotifyRetryable(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, p := range []string{"timeout", "connection refused", "connection reset", "EOF"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	if code := extractHTTPStatus(s); code > 0 {
		return code >= 500
	}
	return false
}

func extractHTTPStatus(s string) int {
	prefix := "status callback returned "
	i := strings.Index(s, prefix)
	if i >= 0 {
		code, _ := strconv.Atoi(strings.TrimSpace(s[i+len(prefix):]))
		return code
	}
	return 0
}
