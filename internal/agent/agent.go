package agent

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"
)

// AgentConfig holds the agent's configuration.
type AgentConfig struct {
	SystemPrompt string
	MaxTurns     int
	Timeout      time.Duration
	OnText       func(text string)
	OnToolCall   func(name string, args map[string]any)
	OnToolResult func(name string, result *ToolResult)
}

// AgentResult represents the result of an agent's execution.
type AgentResult struct {
	Text     string
	Turns    int
	Duration time.Duration
	Error    error
}

// AgentOption configures an Agent.
type AgentOption func(*Agent)

func WithSystemPrompt(prompt string) AgentOption {
	return func(a *Agent) { a.config.SystemPrompt = prompt }
}

func WithMaxTurns(n int) AgentOption {
	return func(a *Agent) {
		if n > 0 {
			a.config.MaxTurns = n
		}
	}
}

func WithAgentTimeout(d time.Duration) AgentOption {
	return func(a *Agent) { a.config.Timeout = d }
}

func WithOnText(fn func(string)) AgentOption {
	return func(a *Agent) { a.config.OnText = fn }
}

func WithOnToolCall(fn func(string, map[string]any)) AgentOption {
	return func(a *Agent) { a.config.OnToolCall = fn }
}

func WithOnToolResult(fn func(string, *ToolResult)) AgentOption {
	return func(a *Agent) { a.config.OnToolResult = fn }
}

// Agent is an AI agent that uses tools to accomplish tasks.
type Agent struct {
	name     string
	client   Client
	executor *Executor
	config   AgentConfig
}

// NewAgent creates a new agent.
func NewAgent(name string, client Client, registry *Registry, opts ...AgentOption) *Agent {
	a := &Agent{
		name:   name,
		client: client,
		config: AgentConfig{
			MaxTurns: 30,
			Timeout:  10 * time.Minute,
		},
	}
	a.executor = NewExecutor(registry)

	for _, opt := range opts {
		opt(a)
	}

	if a.config.SystemPrompt != "" {
		a.client.SetSystemInstruction(a.config.SystemPrompt)
	}
	a.client.SetTools(registry.Declarations())

	return a
}

// Run executes the agent with the given message.
func (a *Agent) Run(ctx context.Context, message string) (*AgentResult, error) {
	start := time.Now()

	if a.config.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, a.config.Timeout)
		defer cancel()
	}

	history := make([]*Content, 0)
	turns := 0

	callHistory := make(map[string]int)
	var callHistoryMu sync.Mutex

	stream, err := a.client.SendMessageWithHistory(ctx, history, message)
	if err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
	}

	history = append(history, NewTextContent("user", message))

	for turns < a.config.MaxTurns {
		turns++

		// Process chunks in real-time — stream text to callback as it arrives
		resp, err := a.collectWithStreaming(ctx, stream)
		if err != nil {
			return &AgentResult{Turns: turns, Duration: time.Since(start), Error: err}, err
		}

		modelContent := buildModelContent(resp)
		history = append(history, modelContent)

		if len(resp.FunctionCalls) == 0 {
			return &AgentResult{
				Text:     resp.Text,
				Turns:    turns,
				Duration: time.Since(start),
			}, nil
		}

		// Loop detection
		loopDetected := false
		for _, fc := range resp.FunctionCalls {
			key := fmt.Sprintf("%s:%v", fc.Name, fc.Args)
			callHistoryMu.Lock()
			callHistory[key]++
			count := callHistory[key]
			callHistoryMu.Unlock()

			if count >= 3 {
				intervention := fmt.Sprintf(
					"LOOP DETECTED: Tool '%s' called %d times with same arguments. Try a different approach.",
					fc.Name, count,
				)
				history = append(history, NewTextContent("user", intervention))
				callHistoryMu.Lock()
				callHistory[key] = 0
				callHistoryMu.Unlock()
				loopDetected = true
				break
			}

			if a.config.OnToolCall != nil {
				a.config.OnToolCall(fc.Name, fc.Args)
			}
		}

		if loopDetected {
			stream, err = a.client.SendMessageWithHistory(ctx, history, "")
			if err != nil {
				return &AgentResult{Turns: turns, Duration: time.Since(start), Error: err}, err
			}
			continue
		}

		// Execute tools
		results, err := a.executor.Execute(ctx, resp.FunctionCalls)
		if err != nil {
			return &AgentResult{Turns: turns, Duration: time.Since(start), Error: err}, err
		}

		// Notify tool results
		if a.config.OnToolResult != nil {
			for i, fc := range resp.FunctionCalls {
				if i < len(results) {
					r := results[i].Response
					tr := &ToolResult{Success: true}
					if s, ok := r["success"].(bool); ok && !s {
						tr.Success = false
						tr.Error, _ = r["error"].(string)
					} else {
						tr.Content, _ = r["content"].(string)
					}
					a.config.OnToolResult(fc.Name, tr)
				}
			}
		}

		// Add function results to history
		funcParts := make([]Part, len(results))
		for j, result := range results {
			funcParts[j] = Part{FunctionResponse: result}
		}
		history = append(history, &Content{Role: "user", Parts: funcParts})

		stream, err = a.client.SendFunctionResponse(ctx, history, results)
		if err != nil {
			return &AgentResult{Turns: turns, Duration: time.Since(start), Error: err}, err
		}
	}

	return &AgentResult{
		Text:     "Max turns reached",
		Turns:    turns,
		Duration: time.Since(start),
		Error:    fmt.Errorf("agent reached maximum turn limit (%d)", a.config.MaxTurns),
	}, nil
}

// collectWithStreaming processes chunks in real-time, calling OnText per chunk.
func (a *Agent) collectWithStreaming(ctx context.Context, sr *StreamResponse) (*Response, error) {
	resp := &Response{}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case chunk, ok := <-sr.Chunks:
			if !ok {
				return resp, nil
			}
			if chunk.Error != nil {
				return nil, chunk.Error
			}

			// Stream text to callback immediately as each chunk arrives
			if chunk.Text != "" {
				if a.config.OnText != nil {
					a.config.OnText(chunk.Text)
				}
				resp.Text += chunk.Text
			}

			resp.FunctionCalls = append(resp.FunctionCalls, chunk.FunctionCalls...)

			if chunk.InputTokens > 0 {
				resp.InputTokens = chunk.InputTokens
			}
			if chunk.OutputTokens > 0 {
				resp.OutputTokens += chunk.OutputTokens
			}

			if chunk.Done {
				resp.FinishReason = chunk.FinishReason
				return resp, nil
			}
		}
	}
}

func buildModelContent(resp *Response) *Content {
	var parts []Part
	if resp.Text != "" {
		parts = append(parts, Part{Text: resp.Text})
	}
	for _, fc := range resp.FunctionCalls {
		parts = append(parts, Part{FunctionCall: fc})
	}
	if len(parts) == 0 {
		parts = append(parts, Part{Text: " "})
	}
	return &Content{Role: "model", Parts: parts}
}

// GenerateID generates a short random hex ID.
func GenerateID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}
