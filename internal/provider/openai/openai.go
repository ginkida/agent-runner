// Package openai implements agent.Client for OpenAI Chat Completions API.
package openai

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

// Option configures an Client.
type Option func(*Client)

func WithBaseURL(url string) Option {
	return func(c *Client) { c.baseURL = strings.TrimSuffix(url, "/") }
}

func WithMaxTokens(n int32) Option {
	return func(c *Client) { c.maxTokens = n }
}

func WithTemperature(t float32) Option {
	return func(c *Client) { c.temperature = &t }
}

func WithMaxRetries(n int) Option {
	return func(c *Client) { c.maxRetries = n }
}

func WithCircuitBreaker(cb *resilience.CircuitBreaker) Option {
	return func(c *Client) { c.cb = cb }
}

// Client implements agent.Client for OpenAI.
type Client struct {
	apiKey            string
	baseURL           string
	model             string
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
	if model == "" {
		return nil, fmt.Errorf("model name is required")
	}

	c := &Client{
		apiKey:     apiKey,
		baseURL:    "https://api.openai.com/v1",
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
	for _, opt := range opts {
		opt(c)
	}
	return c, nil
}

func (c *Client) SendMessage(ctx context.Context, message string) (*agent.StreamResponse, error) {
	return c.SendMessageWithHistory(ctx, nil, message)
}

func (c *Client) SendMessageWithHistory(ctx context.Context, history []*agent.Content, message string) (*agent.StreamResponse, error) {
	c.mu.RLock()
	sys := c.systemInstruction
	c.mu.RUnlock()

	messages := convertHistory(history, message, sys)
	body := map[string]any{
		"model":    c.model,
		"messages": messages,
		"stream":   true,
	}
	if c.maxTokens > 0 {
		if isReasoningModel(c.model) {
			body["max_completion_tokens"] = c.maxTokens
		} else {
			body["max_tokens"] = c.maxTokens
		}
	}
	// Reasoning models (o1, o3) do not support temperature.
	if c.temperature != nil && !isReasoningModel(c.model) {
		body["temperature"] = *c.temperature
	}
	c.mu.RLock()
	if len(c.tools) > 0 {
		body["tools"] = convertTools(c.tools)
	}
	c.mu.RUnlock()

	return c.streamRequest(ctx, body)
}

func (c *Client) SendFunctionResponse(ctx context.Context, history []*agent.Content, results []*agent.FunctionResponse) (*agent.StreamResponse, error) {
	c.mu.RLock()
	sys := c.systemInstruction
	c.mu.RUnlock()

	messages := convertHistoryWithResults(history, results, sys)
	body := map[string]any{
		"model":    c.model,
		"messages": messages,
		"stream":   true,
	}
	if c.maxTokens > 0 {
		if isReasoningModel(c.model) {
			body["max_completion_tokens"] = c.maxTokens
		} else {
			body["max_tokens"] = c.maxTokens
		}
	}
	// Reasoning models (o1, o3) do not support temperature.
	if c.temperature != nil && !isReasoningModel(c.model) {
		body["temperature"] = *c.temperature
	}
	c.mu.RLock()
	if len(c.tools) > 0 {
		body["tools"] = convertTools(c.tools)
	}
	c.mu.RUnlock()

	return c.streamRequest(ctx, body)
}

func (c *Client) SetTools(tools []*agent.FunctionDeclaration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.tools = tools
}

func (c *Client) SetSystemInstruction(instruction string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.systemInstruction = instruction
}

func (c *Client) GetModel() string { return c.model }
// isReasoningModel returns true for OpenAI reasoning models (o1, o3 families)
// which use max_completion_tokens instead of max_tokens and don't support temperature.
func isReasoningModel(model string) bool {
	return model == "o1" || model == "o3" ||
		strings.HasPrefix(model, "o1-") || strings.HasPrefix(model, "o3-")
}

func (c *Client) Close() error     { return nil }

// --- streaming ---

func (c *Client) streamRequest(ctx context.Context, requestBody map[string]any) (*agent.StreamResponse, error) {
	var result *agent.StreamResponse
	err := c.executeWithCB(func() error {
		return resilience.RetryWithBackoff(ctx, resilience.RetryConfig{
			MaxRetries:  c.maxRetries,
			BaseDelay:   c.retryDelay,
			MaxDelay:    30 * time.Second,
			IsRetryable: isRetryable,
		}, func() error {
			r, e := c.doRequest(ctx, requestBody)
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

func (c *Client) doRequest(ctx context.Context, requestBody map[string]any) (*agent.StreamResponse, error) {
	data, err := json.Marshal(requestBody)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.baseURL+"/chat/completions", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
		if readErr != nil {
			return nil, fmt.Errorf("API error (status %d): body read failed: %v", resp.StatusCode, readErr)
		}
		return nil, fmt.Errorf("API error (status %d): %s", resp.StatusCode, body)
	}

	chunks := make(chan agent.ResponseChunk, 10)
	done := make(chan struct{})

	go func() {
		defer close(chunks)
		defer close(done)
		defer resp.Body.Close()

		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024) // 1MB max line
		acc := &toolAcc{active: make(map[int]*pendingCall)}

		for scanner.Scan() {
			line := scanner.Text()
			d := extractData(line)
			if d == "" {
				continue
			}
			if d == "[DONE]" {
				chunk := agent.ResponseChunk{Done: true}
				if len(acc.completed) > 0 {
					chunk.FunctionCalls = acc.completed
				}
				trySend(ctx, chunks, chunk)
				return
			}
			var ev chatChunk
			if json.Unmarshal([]byte(d), &ev) != nil {
				continue
			}
			chunk := processChunk(&ev, acc)
			if chunk.Text != "" || chunk.Done || len(chunk.FunctionCalls) > 0 {
				if !trySend(ctx, chunks, chunk) {
					return
				}
			}
		}
		if err := scanner.Err(); err != nil {
			trySend(ctx, chunks, agent.ResponseChunk{Error: fmt.Errorf("stream read: %w", err)})
			return
		}
		// Fallback done chunk if stream closed without [DONE]
		trySend(ctx, chunks, agent.ResponseChunk{Done: true, FinishReason: agent.FinishReasonStop})
	}()

	return &agent.StreamResponse{Chunks: chunks, Done: done}, nil
}

// --- SSE chunk types ---

type chatChunk struct {
	Choices []struct {
		Delta struct {
			Content   string     `json:"content"`
			ToolCalls []toolCall `json:"tool_calls"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

type toolCall struct {
	Index    int    `json:"index"`
	ID       string `json:"id"`
	Function struct {
		Name      string `json:"name"`
		Arguments string `json:"arguments"`
	} `json:"function"`
}

type pendingCall struct {
	id   string
	name string
	args strings.Builder
}

type toolAcc struct {
	active    map[int]*pendingCall
	completed []*agent.FunctionCall
}

func processChunk(ev *chatChunk, acc *toolAcc) agent.ResponseChunk {
	chunk := agent.ResponseChunk{}
	if ev.Usage != nil {
		chunk.InputTokens = ev.Usage.PromptTokens
		chunk.OutputTokens = ev.Usage.CompletionTokens
	}
	if len(ev.Choices) == 0 {
		return chunk
	}
	ch := ev.Choices[0]
	if ch.Delta.Content != "" {
		chunk.Text = ch.Delta.Content
	}
	for _, tc := range ch.Delta.ToolCalls {
		p, ok := acc.active[tc.Index]
		if !ok {
			p = &pendingCall{}
			acc.active[tc.Index] = p
		}
		if tc.ID != "" {
			p.id = tc.ID
		}
		if tc.Function.Name != "" {
			p.name = tc.Function.Name
		}
		if tc.Function.Arguments != "" {
			p.args.WriteString(tc.Function.Arguments)
		}
	}
	if ch.FinishReason != "" {
		switch ch.FinishReason {
		case "stop":
			chunk.Done = true
			chunk.FinishReason = agent.FinishReasonStop
		case "length":
			chunk.Done = true
			chunk.FinishReason = agent.FinishReasonMaxTokens
		case "tool_calls":
			for _, p := range acc.active {
				acc.completed = append(acc.completed, finalize(p))
			}
			chunk.FunctionCalls = acc.completed
			chunk.Done = true
			chunk.FinishReason = agent.FinishReasonStop
		}
	}
	return chunk
}

func finalize(p *pendingCall) *agent.FunctionCall {
	var args map[string]any
	if raw := p.args.String(); raw != "" {
		if json.Unmarshal([]byte(raw), &args) != nil {
			args = map[string]any{}
		}
	}
	id := p.id
	if id == "" {
		id = randomID()
	}
	return &agent.FunctionCall{ID: id, Name: p.name, Args: args}
}

// --- history conversion ---

func convertHistory(history []*agent.Content, newMessage, sys string) []map[string]any {
	msgs := make([]map[string]any, 0)
	if sys != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": sys})
	}
	for _, c := range history {
		msgs = append(msgs, contentToMsgs(c)...)
	}
	if newMessage == "" {
		newMessage = "Continue."
	}
	msgs = append(msgs, map[string]any{"role": "user", "content": newMessage})
	return msgs
}

func convertHistoryWithResults(history []*agent.Content, _ []*agent.FunctionResponse, sys string) []map[string]any {
	msgs := make([]map[string]any, 0)
	if sys != "" {
		msgs = append(msgs, map[string]any{"role": "system", "content": sys})
	}
	for _, c := range history {
		msgs = append(msgs, contentToMsgs(c)...)
	}
	// Results are already included in history (added by the agent loop
	// before calling SendFunctionResponse), so we don't append them again.
	// Duplicating them would create tool messages without matching
	// preceding assistant tool_calls, which OpenAI rejects.
	return msgs
}

func contentToMsgs(c *agent.Content) []map[string]any {
	var out []map[string]any
	if c.Role == "user" {
		var toolResults []map[string]any
		var texts []string
		for _, p := range c.Parts {
			if p.FunctionResponse != nil {
				toolResults = append(toolResults, map[string]any{
					"role":         "tool",
					"tool_call_id": nonEmpty(p.FunctionResponse.ID, p.FunctionResponse.Name),
					"content":      resultContent(p.FunctionResponse),
				})
			} else if p.Text != "" {
				texts = append(texts, p.Text)
			}
		}
		out = append(out, toolResults...)
		if len(texts) > 0 {
			out = append(out, map[string]any{"role": "user", "content": strings.Join(texts, "\n")})
		}
		if len(out) == 0 {
			out = append(out, map[string]any{"role": "user", "content": "Continue."})
		}
	} else if c.Role == "model" {
		msg := map[string]any{"role": "assistant"}
		var texts []string
		var tcs []map[string]any
		for _, p := range c.Parts {
			if p.Text != "" {
				texts = append(texts, p.Text)
			}
			if p.FunctionCall != nil {
				argsJSON, _ := json.Marshal(p.FunctionCall.Args)
				tcs = append(tcs, map[string]any{
					"id":   nonEmpty(p.FunctionCall.ID, randomID()),
					"type": "function",
					"function": map[string]any{
						"name":      p.FunctionCall.Name,
						"arguments": string(argsJSON),
					},
				})
			}
		}
		if len(texts) > 0 {
			msg["content"] = strings.Join(texts, "\n")
		}
		if len(tcs) > 0 {
			msg["tool_calls"] = tcs
		}
		out = append(out, msg)
	}
	return out
}

func convertTools(tools []*agent.FunctionDeclaration) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  schemaToJSON(t.Parameters),
			},
		})
	}
	return out
}

func schemaToJSON(s *agent.Schema) map[string]any {
	if s == nil {
		return map[string]any{"type": "object", "properties": map[string]any{}}
	}
	m := map[string]any{"type": string(s.Type)}
	if s.Description != "" {
		m["description"] = s.Description
	}
	if len(s.Enum) > 0 {
		m["enum"] = s.Enum
	}
	if len(s.Properties) > 0 {
		props := make(map[string]any)
		for k, v := range s.Properties {
			props[k] = schemaToJSON(v)
		}
		m["properties"] = props
	}
	if len(s.Required) > 0 {
		m["required"] = s.Required
	}
	if s.Items != nil {
		m["items"] = schemaToJSON(s.Items)
	}
	return m
}

// --- helpers ---

func resultContent(r *agent.FunctionResponse) string {
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

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func extractData(line string) string {
	if strings.HasPrefix(line, "data: ") {
		return strings.TrimPrefix(line, "data: ")
	}
	if strings.HasPrefix(line, "data:") {
		return strings.TrimPrefix(line, "data:")
	}
	return ""
}

func trySend(ctx context.Context, ch chan<- agent.ResponseChunk, chunk agent.ResponseChunk) bool {
	select {
	case ch <- chunk:
		return true
	case <-ctx.Done():
		return false
	}
}

func randomID() string {
	b := make([]byte, 12)
	rand.Read(b)
	return "call_" + hex.EncodeToString(b)
}

func isRetryable(err error) bool {
	if err == nil {
		return false
	}
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
