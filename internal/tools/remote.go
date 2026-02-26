package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ginkida/agent-runner/internal/agent"
	"github.com/ginkida/agent-runner/internal/auth"
	"github.com/ginkida/agent-runner/internal/netutil"
	"github.com/ginkida/agent-runner/internal/resilience"
)

// validToolName restricts tool names to safe identifiers.
var validToolName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9_]*$`)

// RemoteTool implements agent.Tool by forwarding execution to Laravel via HTTP callback.
type RemoteTool struct {
	name        string
	description string
	schema      *agent.Schema
	callbackURL string
	hmacSecret  string
	sessionID   string
	httpClient  *http.Client
}

// RemoteToolConfig holds configuration for creating a RemoteTool.
type RemoteToolConfig struct {
	Name            string
	Description     string
	Schema          *agent.Schema
	CallbackBaseURL string
	HMACSecret      string
	SessionID       string
	TimeoutSec      int
}

// NewRemoteTool creates a remote tool that calls back to Laravel.
// It validates the tool name and ensures the callback URL stays within the base URL's host.
func NewRemoteTool(cfg RemoteToolConfig) (*RemoteTool, error) {
	if !validToolName.MatchString(cfg.Name) {
		return nil, fmt.Errorf("invalid tool name %q: must match [a-zA-Z][a-zA-Z0-9_]*", cfg.Name)
	}

	timeout := 30 * time.Second
	if cfg.TimeoutSec > 0 {
		timeout = time.Duration(cfg.TimeoutSec) * time.Second
	}

	callbackURL := strings.TrimSuffix(cfg.CallbackBaseURL, "/") + "/tools/" + cfg.Name

	// Validate that the final URL matches the base URL host and path prefix
	baseURL, err := url.Parse(cfg.CallbackBaseURL)
	if err != nil {
		return nil, fmt.Errorf("invalid callback base URL: %w", err)
	}
	finalURL, err := url.Parse(callbackURL)
	if err != nil {
		return nil, fmt.Errorf("invalid callback URL: %w", err)
	}
	if baseURL.Host != finalURL.Host || baseURL.Scheme != finalURL.Scheme {
		return nil, fmt.Errorf("callback URL host mismatch: base=%s final=%s", baseURL.Host, finalURL.Host)
	}

	return &RemoteTool{
		name:        cfg.Name,
		description: cfg.Description,
		schema:      cfg.Schema,
		callbackURL: callbackURL,
		hmacSecret:  cfg.HMACSecret,
		sessionID:   cfg.SessionID,
		httpClient:  &http.Client{Timeout: timeout, Transport: netutil.SafeTransport()},
	}, nil
}

func (t *RemoteTool) Name() string        { return t.name }
func (t *RemoteTool) Description() string { return t.description }

func (t *RemoteTool) Declaration() *agent.FunctionDeclaration {
	return &agent.FunctionDeclaration{
		Name:        t.name,
		Description: t.description,
		Parameters:  t.schema,
	}
}

func (t *RemoteTool) Execute(ctx context.Context, args map[string]any) (*agent.ToolResult, error) {
	payload := map[string]any{
		"session_id": t.sessionID,
		"tool_name":  t.name,
		"arguments":  args,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return agent.NewErrorResult(fmt.Sprintf("marshal error: %v", err)), nil
	}

	var result *agent.ToolResult
	err = resilience.RetryWithBackoff(ctx, resilience.RetryConfig{
		MaxRetries:  3,
		BaseDelay:   time.Second,
		MaxDelay:    10 * time.Second,
		IsRetryable: isCallbackRetryable,
	}, func() error {
		r, callErr := t.doCallback(ctx, body)
		if callErr != nil {
			return callErr
		}
		result = r
		return nil
	})

	if err != nil {
		return agent.NewErrorResult(fmt.Sprintf("callback failed after retries: %v", err)), nil
	}
	return result, nil
}

func (t *RemoteTool) doCallback(ctx context.Context, body []byte) (*agent.ToolResult, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", t.callbackURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("request error: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Session-ID", t.sessionID)

	if t.hmacSecret != "" {
		sig, ts, nonce := auth.SignRequest(t.hmacSecret, body)
		req.Header.Set("X-Signature", sig)
		req.Header.Set("X-Timestamp", ts)
		req.Header.Set("X-Nonce", nonce)
	}

	resp, err := t.httpClient.Do(req)
	if err != nil {
		return nil, err // network error → retryable
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 200*1024))
	if err != nil {
		return nil, fmt.Errorf("read response: %v", err)
	}

	if resp.StatusCode >= 500 {
		return nil, fmt.Errorf("callback returned %d: %s", resp.StatusCode, string(respBody))
	}

	if resp.StatusCode >= 400 {
		// Client errors are not retryable — return as tool error
		return agent.NewErrorResult(fmt.Sprintf("callback returned %d: %s", resp.StatusCode, string(respBody))), nil
	}

	var parsed struct {
		Success bool   `json:"success"`
		Content string `json:"content"`
		Error   string `json:"error"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return nil, fmt.Errorf("parse response: %v", err)
	}

	if !parsed.Success {
		return agent.NewErrorResult(parsed.Error), nil
	}
	return agent.NewSuccessResult(parsed.Content), nil
}

func isCallbackRetryable(err error) bool {
	if err == nil {
		return false
	}
	s := err.Error()
	for _, p := range []string{"timeout", "connection refused", "connection reset", "EOF", "broken pipe"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	if code := extractCallbackStatus(s); code > 0 {
		return code >= 500
	}
	return false
}

func extractCallbackStatus(s string) int {
	prefix := "callback returned "
	i := strings.Index(s, prefix)
	if i < 0 {
		return 0
	}
	rest := s[i+len(prefix):]
	end := strings.IndexByte(rest, ':')
	if end < 0 {
		end = len(rest)
	}
	code, _ := strconv.Atoi(strings.TrimSpace(rest[:end]))
	return code
}
