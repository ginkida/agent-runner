package session

import (
	"context"
	"sync"
	"time"

	"github.com/ginkida/agent-runner/internal/agent"
	"github.com/ginkida/agent-runner/internal/sse"
)

// Status represents the session lifecycle state.
type Status string

const (
	StatusCreated   Status = "created"
	StatusRunning   Status = "running"
	StatusCompleted Status = "completed"
	StatusFailed    Status = "failed"
	StatusCancelled Status = "cancelled"
)

// AgentDefinition describes the agent configuration sent by Laravel.
type AgentDefinition struct {
	Name         string          `json:"name"`
	SystemPrompt string          `json:"system_prompt"`
	Model        string          `json:"model"`
	MaxTurns     int             `json:"max_turns"`
	MaxTokens    int32           `json:"max_tokens,omitempty"`
	Temperature  *float32        `json:"temperature,omitempty"`
	Tools        ToolsDefinition `json:"tools"`
}

// SessionOptions holds optional per-session overrides provided at creation time.
type SessionOptions struct {
	WorkDir         string
	CallbackBaseURL string
	CallbackTimeout int
}

// ToolsDefinition specifies which tools to register.
type ToolsDefinition struct {
	Builtin []string        `json:"builtin"`
	Remote  []RemoteToolDef `json:"remote"`
}

// RemoteToolDef describes a tool that calls back to Laravel.
type RemoteToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"` // JSON Schema
}

// Session holds the state for a single agent execution session.
type Session struct {
	ID              string
	ClientID        string
	AgentDef        AgentDefinition
	WorkDir         string
	CallbackBaseURL string
	CallbackTimeout int
	Status          Status
	Events          chan sse.Event
	Cancel          func()
	Result          *agent.AgentResult
	Error           string
	CreatedAt       time.Time
	LastActive      time.Time
	CompletedAt     time.Time
	mu              sync.RWMutex
	closeOnce       sync.Once
	eventsDone      chan struct{}
}

// NewSession creates a new session with the given definition and options.
func NewSession(id, clientID string, def AgentDefinition, opts SessionOptions) *Session {
	return &Session{
		ID:              id,
		ClientID:        clientID,
		AgentDef:        def,
		WorkDir:         opts.WorkDir,
		CallbackBaseURL: opts.CallbackBaseURL,
		CallbackTimeout: opts.CallbackTimeout,
		Status:          StatusCreated,
		Events:          make(chan sse.Event, 64),
		CreatedAt:       time.Now(),
		LastActive:      time.Now(),
		eventsDone:      make(chan struct{}),
	}
}

// SetStatus atomically updates the session status.
func (s *Session) SetStatus(status Status) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Status = status
	s.LastActive = time.Now()
}

// GetStatus returns the current status.
func (s *Session) GetStatus() Status {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Status
}

// SetResult stores the agent result and sets status.
func (s *Session) SetResult(result *agent.AgentResult) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Result = result
	now := time.Now()
	if result.Error != nil {
		s.Status = StatusFailed
		s.Error = result.Error.Error()
	} else {
		s.Status = StatusCompleted
	}
	s.LastActive = now
	s.CompletedAt = now
}

// SetError stores an error and sets status to failed.
func (s *Session) SetError(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	s.Status = StatusFailed
	s.Error = err.Error()
	s.LastActive = now
	s.CompletedAt = now
}

// TryStart atomically transitions the session from a non-running state to running.
// Returns false if the session is already running (prevents double-start TOCTOU).
func (s *Session) TryStart() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Status == StatusRunning {
		return false
	}
	s.Status = StatusRunning
	s.LastActive = time.Now()
	return true
}

// SendEvent sends an event to the Events channel, respecting context cancellation.
// Returns true if the event was sent, false if the channel is closed, context is done,
// or the send doesn't complete within 5 seconds (reader disconnected, buffer full).
func (s *Session) SendEvent(ctx context.Context, event sse.Event) bool {
	select {
	case <-s.eventsDone:
		return false
	default:
	}
	select {
	case s.Events <- event:
		return true
	case <-ctx.Done():
		return false
	case <-s.eventsDone:
		return false
	case <-time.After(5 * time.Second):
		return false
	}
}

// CloseEvents signals that no more events will be sent and drains buffered events.
// It does NOT close the Events channel to avoid send-on-closed-channel panics
// from concurrent SendEvent calls.
func (s *Session) CloseEvents() {
	s.closeOnce.Do(func() {
		close(s.eventsDone)
		// Drain buffered events; do NOT close Events to avoid send-on-closed panic.
		for {
			select {
			case <-s.Events:
			default:
				return
			}
		}
	})
}

// SetCancel atomically sets the cancel function.
func (s *Session) SetCancel(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Cancel = fn
}

// CancelIfRunning atomically reads and calls the cancel function if set.
func (s *Session) CancelIfRunning() {
	s.mu.RLock()
	fn := s.Cancel
	s.mu.RUnlock()
	if fn != nil {
		fn()
	}
}

// Touch updates the last active time.
func (s *Session) Touch() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.LastActive = time.Now()
}

// Info returns a snapshot of the session for API responses.
func (s *Session) Info() SessionInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info := SessionInfo{
		ID:        s.ID,
		Name:      s.AgentDef.Name,
		Model:     s.AgentDef.Model,
		Status:    string(s.Status),
		CreatedAt: s.CreatedAt,
	}

	if s.Result != nil {
		info.Output = s.Result.Text
		info.Turns = s.Result.Turns
		info.DurationMs = s.Result.Duration.Milliseconds()
	}
	if s.Error != "" {
		info.Error = s.Error
	}

	return info
}

// SessionInfo is the JSON-serializable session status.
type SessionInfo struct {
	ID         string    `json:"session_id"`
	Name       string    `json:"name"`
	Model      string    `json:"model"`
	Status     string    `json:"status"`
	Output     string    `json:"output,omitempty"`
	Error      string    `json:"error,omitempty"`
	Turns      int       `json:"turns,omitempty"`
	DurationMs int64     `json:"duration_ms,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}
