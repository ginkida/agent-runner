// Package gemini implements agent.Client for Gemini REST API (no SDK dependency).
package gemini

import (
	"bufio"
	"bytes"
	"context"
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

func WithTemperature(t float32) Option { return func(c *Client) { c.temperature = &t } }
func WithMaxTokens(n int32) Option     { return func(c *Client) { c.maxTokens = n } }
func WithMaxRetries(n int) Option      { return func(c *Client) { c.maxRetries = n } }
func WithCircuitBreaker(cb *resilience.CircuitBreaker) Option {
	return func(c *Client) { c.cb = cb }
}

type Client struct {
	apiKey, model     string
	temperature       *float32
	maxTokens         int32
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
	contents := toGeminiContents(history, msg)
	return c.doStream(ctx, contents)
}

func (c *Client) SendFunctionResponse(ctx context.Context, history []*agent.Content, results []*agent.FunctionResponse) (*agent.StreamResponse, error) {
	contents := toGeminiContentsRaw(history)
	// Append function response parts
	parts := make([]map[string]any, 0, len(results))
	for _, r := range results {
		parts = append(parts, map[string]any{
			"functionResponse": map[string]any{
				"name":     r.Name,
				"response": r.Response,
			},
		})
	}
	contents = append(contents, map[string]any{"role": "user", "parts": parts})
	return c.doStream(ctx, contents)
}

func (c *Client) SetTools(t []*agent.FunctionDeclaration)  { c.mu.Lock(); c.tools = t; c.mu.Unlock() }
func (c *Client) SetSystemInstruction(s string)            { c.mu.Lock(); c.systemInstruction = s; c.mu.Unlock() }
func (c *Client) GetModel() string                         { return c.model }
func (c *Client) Close() error                             { return nil }

func (c *Client) doStream(ctx context.Context, contents []map[string]any) (*agent.StreamResponse, error) {
	c.mu.RLock()
	sys := c.systemInstruction
	tools := c.tools
	c.mu.RUnlock()

	body := map[string]any{"contents": contents}

	if sys != "" {
		body["systemInstruction"] = map[string]any{
			"parts": []map[string]any{{"text": sys}},
		}
	}

	genCfg := map[string]any{}
	if c.temperature != nil {
		genCfg["temperature"] = *c.temperature
	}
	if c.maxTokens > 0 {
		genCfg["maxOutputTokens"] = c.maxTokens
	}
	if len(genCfg) > 0 {
		body["generationConfig"] = genCfg
	}

	if len(tools) > 0 {
		body["tools"] = []map[string]any{
			{"functionDeclarations": convertToolsGemini(tools)},
		}
	}

	var result *agent.StreamResponse
	err := c.executeWithCB(func() error {
		return resilience.RetryWithBackoff(ctx, resilience.RetryConfig{
			MaxRetries:  c.maxRetries,
			BaseDelay:   c.retryDelay,
			MaxDelay:    30 * time.Second,
			IsRetryable: retryable,
		}, func() error {
			r, e := c.doHTTP(ctx, body)
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

func (c *Client) doHTTP(ctx context.Context, body map[string]any) (*agent.StreamResponse, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal: %w", err)
	}
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:streamGenerateContent?alt=sse", c.model)

	req, err := http.NewRequestWithContext(ctx, "POST", url, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", c.apiKey)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	if resp.StatusCode != 200 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		resp.Body.Close()
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
		for scanner.Scan() {
			line := scanner.Text()
			d := extractData(line)
			if d == "" {
				continue
			}
			var ev geminiResponse
			if json.Unmarshal([]byte(d), &ev) != nil {
				continue
			}
			chunk := processGeminiChunk(&ev)
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
		// Final done if not already sent
		select {
		case chunks <- agent.ResponseChunk{Done: true, FinishReason: agent.FinishReasonStop}:
		case <-ctx.Done():
		}
	}()

	return &agent.StreamResponse{Chunks: chunks, Done: done}, nil
}

type geminiResponse struct {
	Candidates []struct {
		Content struct {
			Parts []struct {
				Text         string `json:"text"`
				FunctionCall *struct {
					Name string         `json:"name"`
					Args map[string]any `json:"args"`
				} `json:"functionCall"`
			} `json:"parts"`
		} `json:"content"`
		FinishReason string `json:"finishReason"`
	} `json:"candidates"`
	UsageMetadata *struct {
		PromptTokenCount     int `json:"promptTokenCount"`
		CandidatesTokenCount int `json:"candidatesTokenCount"`
	} `json:"usageMetadata"`
}

func processGeminiChunk(ev *geminiResponse) agent.ResponseChunk {
	chunk := agent.ResponseChunk{}
	if ev.UsageMetadata != nil {
		chunk.InputTokens = ev.UsageMetadata.PromptTokenCount
		chunk.OutputTokens = ev.UsageMetadata.CandidatesTokenCount
	}
	if len(ev.Candidates) == 0 {
		return chunk
	}
	cand := ev.Candidates[0]
	for _, p := range cand.Content.Parts {
		if p.Text != "" {
			chunk.Text += p.Text
		}
		if p.FunctionCall != nil {
			chunk.FunctionCalls = append(chunk.FunctionCalls, &agent.FunctionCall{
				ID:   agent.GenerateID(),
				Name: p.FunctionCall.Name,
				Args: p.FunctionCall.Args,
			})
		}
	}
	switch cand.FinishReason {
	case "STOP":
		chunk.Done = true
		chunk.FinishReason = agent.FinishReasonStop
	case "MAX_TOKENS":
		chunk.Done = true
		chunk.FinishReason = agent.FinishReasonMaxTokens
	}
	return chunk
}

// --- history conversion ---

func toGeminiContents(history []*agent.Content, msg string) []map[string]any {
	out := toGeminiContentsRaw(history)
	if msg == "" {
		msg = "Continue."
	}
	out = append(out, map[string]any{"role": "user", "parts": []map[string]any{{"text": msg}}})
	return out
}

func toGeminiContentsRaw(history []*agent.Content) []map[string]any {
	out := make([]map[string]any, 0, len(history))
	for _, c := range history {
		role := c.Role
		if role == "model" {
			role = "model"
		}
		parts := make([]map[string]any, 0)
		for _, p := range c.Parts {
			if p.Text != "" {
				parts = append(parts, map[string]any{"text": p.Text})
			}
			if p.FunctionCall != nil {
				parts = append(parts, map[string]any{
					"functionCall": map[string]any{"name": p.FunctionCall.Name, "args": p.FunctionCall.Args},
				})
			}
			if p.FunctionResponse != nil {
				parts = append(parts, map[string]any{
					"functionResponse": map[string]any{"name": p.FunctionResponse.Name, "response": p.FunctionResponse.Response},
				})
			}
		}
		if len(parts) > 0 {
			out = append(out, map[string]any{"role": role, "parts": parts})
		}
	}
	return out
}

func convertToolsGemini(tools []*agent.FunctionDeclaration) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		out = append(out, map[string]any{
			"name":        t.Name,
			"description": t.Description,
			"parameters":  schemaToGemini(t.Parameters),
		})
	}
	return out
}

func schemaToGemini(s *agent.Schema) map[string]any {
	if s == nil {
		return map[string]any{"type": "OBJECT", "properties": map[string]any{}}
	}
	m := map[string]any{"type": strings.ToUpper(string(s.Type))}
	if s.Description != "" {
		m["description"] = s.Description
	}
	if len(s.Properties) > 0 {
		p := map[string]any{}
		for k, v := range s.Properties {
			p[k] = schemaToGemini(v)
		}
		m["properties"] = p
	}
	if len(s.Required) > 0 {
		m["required"] = s.Required
	}
	if s.Items != nil {
		m["items"] = schemaToGemini(s.Items)
	}
	if len(s.Enum) > 0 {
		m["enum"] = s.Enum
	}
	return m
}

func extractData(line string) string {
	if strings.HasPrefix(line, "data: ") {
		return strings.TrimPrefix(line, "data: ")
	}
	return ""
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
