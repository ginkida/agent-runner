// Package anthropic implements agent.Client for the Anthropic Messages API.
package anthropic

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ginkida/agent-runner/internal/agent"
	"github.com/ginkida/agent-runner/internal/resilience"
)

type Option func(*Client)

func WithMaxTokens(n int32) Option    { return func(c *Client) { c.maxTokens = n } }
func WithTemperature(t float32) Option { return func(c *Client) { c.temperature = &t } }
func WithMaxRetries(n int) Option      { return func(c *Client) { c.maxRetries = n } }
func WithCircuitBreaker(cb *resilience.CircuitBreaker) Option {
	return func(c *Client) { c.cb = cb }
}

type Client struct {
	apiKey, model     string
	maxTokens         int32
	temperature       *float32
	maxRetries        int
	retryDelay        time.Duration
	httpClient        *http.Client
	tools             []*agent.FunctionDeclaration
	systemInstruction string
	cb                *resilience.CircuitBreaker
	mu                sync.RWMutex
}

func New(apiKey, model string, opts ...Option) (*Client, error) {
	if apiKey == "" {
		return nil, fmt.Errorf("API key is required")
	}
	c := &Client{
		apiKey:     apiKey,
		model:      model,
		maxTokens:  4096,
		maxRetries: 3,
		retryDelay: time.Second,
		httpClient: &http.Client{
			Transport: &http.Transport{
				ResponseHeaderTimeout: 30 * time.Second,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
			},
		},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

func (c *Client) SendMessage(ctx context.Context, msg string) (*agent.StreamResponse, error) {
	return c.SendMessageWithHistory(ctx, nil, msg)
}

func (c *Client) SendMessageWithHistory(ctx context.Context, history []*agent.Content, msg string) (*agent.StreamResponse, error) {
	c.mu.RLock()
	sys := c.systemInstruction
	tools := c.tools
	c.mu.RUnlock()

	messages := toAnthropicMsgs(history, msg)
	body := map[string]any{"model": c.model, "max_tokens": c.maxTokens, "messages": messages, "stream": true}
	if sys != "" {
		body["system"] = sys
	}
	if c.temperature != nil {
		body["temperature"] = *c.temperature
	}
	if len(tools) > 0 {
		body["tools"] = convertToolsAnthropic(tools)
	}
	return c.stream(ctx, body)
}

func (c *Client) SendFunctionResponse(ctx context.Context, history []*agent.Content, results []*agent.FunctionResponse) (*agent.StreamResponse, error) {
	c.mu.RLock()
	sys := c.systemInstruction
	tools := c.tools
	c.mu.RUnlock()

	messages := toAnthropicMsgsWithResults(history, results)
	body := map[string]any{"model": c.model, "max_tokens": c.maxTokens, "messages": messages, "stream": true}
	if sys != "" {
		body["system"] = sys
	}
	if c.temperature != nil {
		body["temperature"] = *c.temperature
	}
	if len(tools) > 0 {
		body["tools"] = convertToolsAnthropic(tools)
	}
	return c.stream(ctx, body)
}

func (c *Client) SetTools(t []*agent.FunctionDeclaration)  { c.mu.Lock(); c.tools = t; c.mu.Unlock() }
func (c *Client) SetSystemInstruction(s string)            { c.mu.Lock(); c.systemInstruction = s; c.mu.Unlock() }
func (c *Client) GetModel() string                         { return c.model }
func (c *Client) Close() error                             { return nil }

func (c *Client) stream(ctx context.Context, body map[string]any) (*agent.StreamResponse, error) {
	var result *agent.StreamResponse
	err := c.executeWithCB(func() error {
		return resilience.RetryWithBackoff(ctx, resilience.RetryConfig{
			MaxRetries:  c.maxRetries,
			BaseDelay:   c.retryDelay,
			MaxDelay:    30 * time.Second,
			IsRetryable: retryable,
		}, func() error {
			r, e := c.doRequest(ctx, body)
			if e == nil {
				result = r
			}
			return e
		})
	})
	return result, err
}

func (c *Client) executeWithCB(fn func() error) error {
	if c.cb != nil {
		return c.cb.Execute(fn)
	}
	return fn()
}

func (c *Client) doRequest(ctx context.Context, body map[string]any) (*agent.StreamResponse, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, "POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if resp.StatusCode != 200 {
		b, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("API error (%d): body read failed: %v", resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("API error (%d): %s", resp.StatusCode, b)
	}

	chunks := make(chan agent.ResponseChunk, 10)
	done := make(chan struct{})

	go func() {
		defer close(chunks)
		defer close(done)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line
		acc := &anthropicAcc{}

		for scanner.Scan() {
			line := scanner.Text()
			d := extractSSEData(line)
			if d == "" {
				continue
			}
			var ev map[string]any
			if json.Unmarshal([]byte(d), &ev) != nil {
				continue
			}
			chunk := processAnthropicEvent(ev, acc)
			if chunk.Text != "" || chunk.Done || len(chunk.FunctionCalls) > 0 {
				select {
				case chunks <- chunk:
				case <-ctx.Done():
					return
				}
			}
			if chunk.Done {
				return
			}
		}
		if err := scanner.Err(); err != nil {
			select {
			case chunks <- agent.ResponseChunk{Error: fmt.Errorf("stream read: %w", err)}:
			case <-ctx.Done():
			}
			return
		}
		// Fallback done chunk if stream closed without message_stop
		select {
		case chunks <- agent.ResponseChunk{Done: true, FinishReason: agent.FinishReasonStop}:
		case <-ctx.Done():
		}
	}()

	return &agent.StreamResponse{Chunks: chunks, Done: done}, nil
}

type anthropicAcc struct {
	toolID, toolName string
	toolInput        strings.Builder
	completed        []*agent.FunctionCall
}

func processAnthropicEvent(ev map[string]any, acc *anthropicAcc) agent.ResponseChunk {
	chunk := agent.ResponseChunk{}
	evType, _ := ev["type"].(string)

	switch evType {
	case "content_block_start":
		if cb, ok := ev["content_block"].(map[string]any); ok {
			if bt, _ := cb["type"].(string); bt == "tool_use" {
				acc.toolName, _ = cb["name"].(string)
				acc.toolID, _ = cb["id"].(string)
				if acc.toolID == "" {
					acc.toolID = randID()
				}
				acc.toolInput.Reset()
			}
		}
	case "content_block_delta":
		if delta, ok := ev["delta"].(map[string]any); ok {
			dt, _ := delta["type"].(string)
			if dt == "text_delta" {
				chunk.Text, _ = delta["text"].(string)
			}
			if dt == "input_json_delta" {
				if pj, ok := delta["partial_json"].(string); ok {
					acc.toolInput.WriteString(pj)
				}
			}
		}
	case "content_block_stop":
		if acc.toolID != "" && acc.toolName != "" {
			var args map[string]any
			if raw := acc.toolInput.String(); raw != "" {
				json.Unmarshal([]byte(raw), &args)
			}
			if args == nil {
				args = map[string]any{}
			}
			acc.completed = append(acc.completed, &agent.FunctionCall{ID: acc.toolID, Name: acc.toolName, Args: args})
			acc.toolID = ""
			acc.toolName = ""
			acc.toolInput.Reset()
		}
	case "message_delta":
		if delta, ok := ev["delta"].(map[string]any); ok {
			if sr, ok := delta["stop_reason"].(string); ok {
				chunk.Done = true
				switch sr {
				case "end_turn":
					chunk.FinishReason = agent.FinishReasonStop
				case "max_tokens":
					chunk.FinishReason = agent.FinishReasonMaxTokens
				case "tool_use":
					chunk.FunctionCalls = acc.completed
					chunk.FinishReason = agent.FinishReasonStop
				}
			}
		}
	case "message_stop":
		chunk.Done = true
		if len(acc.completed) > 0 {
			chunk.FunctionCalls = acc.completed
		}
	}
	return chunk
}

// --- history conversion ---

func toAnthropicMsgs(history []*agent.Content, newMsg string) []map[string]any {
	msgs := make([]map[string]any, 0)
	for _, c := range history {
		if c.Role == "user" {
			msgs = append(msgs, buildUserMsg(c.Parts))
		} else if c.Role == "model" {
			msgs = append(msgs, buildAssistantMsg(c.Parts))
		}
	}
	if newMsg == "" {
		newMsg = "Continue."
	}
	msgs = append(msgs, map[string]any{"role": "user", "content": []map[string]any{{"type": "text", "text": newMsg}}})
	return msgs
}

func toAnthropicMsgsWithResults(history []*agent.Content, _ []*agent.FunctionResponse) []map[string]any {
	msgs := make([]map[string]any, 0)
	for _, c := range history {
		if c.Role == "user" {
			msgs = append(msgs, buildUserMsg(c.Parts))
		} else if c.Role == "model" {
			msgs = append(msgs, buildAssistantMsg(c.Parts))
		}
	}
	// Results are already included in history (added by the agent loop
	// before calling SendFunctionResponse). buildUserMsg converts
	// FunctionResponse parts to tool_result blocks, so we don't
	// append them again.
	return msgs
}

func buildUserMsg(parts []agent.Part) map[string]any {
	content := make([]map[string]any, 0)
	for _, p := range parts {
		if p.Text != "" {
			content = append(content, map[string]any{"type": "text", "text": p.Text})
		}
		if p.FunctionResponse != nil {
			id := p.FunctionResponse.ID
			if id == "" {
				id = p.FunctionResponse.Name
			}
			content = append(content, map[string]any{"type": "tool_result", "tool_use_id": id, "content": frContent(p.FunctionResponse)})
		}
	}
	if len(content) == 0 {
		content = append(content, map[string]any{"type": "text", "text": "Continue."})
	}
	return map[string]any{"role": "user", "content": content}
}

func buildAssistantMsg(parts []agent.Part) map[string]any {
	content := make([]map[string]any, 0)
	for _, p := range parts {
		if p.Text != "" {
			content = append(content, map[string]any{"type": "text", "text": p.Text})
		}
		if p.FunctionCall != nil {
			id := p.FunctionCall.ID
			if id == "" {
				id = p.FunctionCall.Name
			}
			content = append(content, map[string]any{"type": "tool_use", "id": id, "name": p.FunctionCall.Name, "input": p.FunctionCall.Args})
		}
	}
	if len(content) == 0 {
		content = append(content, map[string]any{"type": "text", "text": " "})
	}
	return map[string]any{"role": "assistant", "content": content}
}

func convertToolsAnthropic(tools []*agent.FunctionDeclaration) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]any{
			"name":         t.Name,
			"description":  t.Description,
			"input_schema": schemaToJSON(t.Parameters),
		})
	}
	return out
}

func schemaToJSON(s *agent.Schema) map[string]any {
	if s == nil {
		return map[string]any{"type": "object"}
	}
	m := map[string]any{}
	if s.Type != "" {
		m["type"] = string(s.Type)
	}
	if s.Description != "" {
		m["description"] = s.Description
	}
	if len(s.Properties) > 0 {
		p := map[string]any{}
		for k, v := range s.Properties {
			p[k] = schemaToJSON(v)
		}
		m["properties"] = p
	}
	if len(s.Required) > 0 {
		m["required"] = s.Required
	}
	if s.Items != nil {
		m["items"] = schemaToJSON(s.Items)
	}
	if len(s.Enum) > 0 {
		m["enum"] = s.Enum
	}
	return m
}

func frContent(r *agent.FunctionResponse) string {
	if r.Response != nil {
		if c, ok := r.Response["content"].(string); ok {
			return c
		}
		if e, ok := r.Response["error"].(string); ok && e != "" {
			return "Error: " + e
		}
	}
	return "Operation completed"
}

func extractSSEData(line string) string {
	if strings.HasPrefix(line, "data: ") {
		return strings.TrimPrefix(line, "data: ")
	}
	if strings.HasPrefix(line, "data:") {
		return strings.TrimPrefix(line, "data:")
	}
	return ""
}

func randID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "toolu_" + hex.EncodeToString(b)
}

func retryable(err error) bool {
	s := err.Error()
	for _, p := range []string{"timeout", "connection refused", "connection reset"} {
		if strings.Contains(s, p) {
			return true
		}
	}
	if code := extractHTTPStatus(s); code > 0 {
		return code == 429 || code >= 500
	}
	return false
}

func extractHTTPStatus(s string) int {
	prefix := "API error ("
	i := strings.Index(s, prefix)
	if i < 0 {
		return 0
	}
	rest := s[i+len(prefix):]
	rest = strings.TrimPrefix(rest, "status ")
	end := strings.IndexByte(rest, ')')
	if end < 0 {
		return 0
	}
	code, _ := strconv.Atoi(rest[:end])
	return code
}
