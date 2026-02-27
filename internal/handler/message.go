package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/ginkida/agent-runner/internal/agent"
	"github.com/ginkida/agent-runner/internal/config"
	"github.com/ginkida/agent-runner/internal/middleware"
	"github.com/ginkida/agent-runner/internal/provider"
	"github.com/ginkida/agent-runner/internal/session"
	"github.com/ginkida/agent-runner/internal/sse"
	"github.com/ginkida/agent-runner/internal/tools"
)

// MessageHandler handles sending messages to agent sessions.
type MessageHandler struct {
	sessions *session.Manager
	cfg      *config.Config
	notifier *session.StatusNotifier
}

// NewMessageHandler creates a new message handler.
func NewMessageHandler(sessions *session.Manager, cfg *config.Config, notifier *session.StatusNotifier) *MessageHandler {
	return &MessageHandler{sessions: sessions, cfg: cfg, notifier: notifier}
}

type messageRequest struct {
	Message string `json:"message"`
}

// Send handles POST /v1/sessions/{id}/messages.
func (h *MessageHandler) Send(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	clientID := middleware.GetClientID(r.Context())
	sess, ok := h.sessions.GetOwned(id, clientID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		return
	}

	var req messageRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid request body: " + err.Error()})
		return
	}
	if req.Message == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "message is required"})
		return
	}

	// Determine model
	model := sess.AgentDef.Model
	if model == "" {
		model = h.cfg.Defaults.Model
	}

	// Determine maxTokens
	maxTokens := sess.AgentDef.MaxTokens
	if maxTokens <= 0 {
		maxTokens = h.cfg.Defaults.MaxTokens
	}

	// Create LLM client
	client, err := provider.NewClient(model, &h.cfg.Providers, &h.cfg.CircuitBreaker, sess.AgentDef.Temperature, maxTokens)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "failed to create client: " + err.Error()})
		return
	}

	// Determine working directory (per-session override or CWD fallback)
	workDir := sess.WorkDir
	if workDir == "" {
		workDir, _ = os.Getwd()
	}

	// Determine callback config (per-session override or global fallback)
	callbackBaseURL := sess.CallbackBaseURL
	if callbackBaseURL == "" {
		callbackBaseURL = h.cfg.Callback.BaseURL
	}
	callbackTimeout := sess.CallbackTimeout
	if callbackTimeout <= 0 {
		callbackTimeout = h.cfg.Callback.TimeoutSec
	}

	// Build tool registry
	registry, registered, err := tools.BuildRegistry(
		sess.AgentDef,
		callbackBaseURL,
		h.cfg.Auth.HMACSecret,
		sess.ID,
		workDir,
		callbackTimeout,
	)
	if err != nil {
		client.Close()
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "failed to build registry: " + err.Error()})
		return
	}

	// Determine max turns and timeout
	maxTurns := sess.AgentDef.MaxTurns
	if maxTurns <= 0 {
		maxTurns = h.cfg.Defaults.MaxTurns
	}
	if maxTurns <= 0 {
		maxTurns = 1
	}
	timeoutSecs := h.cfg.Defaults.TimeoutSecs
	if timeoutSecs <= 0 {
		timeoutSecs = 300
	}

	// Create context for agent lifecycle.
	ctx, cancel := context.WithCancel(context.Background())

	// Create agent with SSE callbacks
	a := agent.NewAgent(sess.AgentDef.Name, client, registry,
		agent.WithSystemPrompt(sess.AgentDef.SystemPrompt),
		agent.WithMaxTurns(maxTurns),
		agent.WithAgentTimeout(time.Duration(timeoutSecs)*time.Second),
		agent.WithOnText(func(text string) {
			sess.Touch()
			sess.SendEvent(ctx, sse.Event{Type: "text", Data: sse.TextData{Content: text}})
		}),
		agent.WithOnToolCall(func(name string, args map[string]any) {
			sess.Touch()
			sess.SendEvent(ctx, sse.Event{Type: "tool_call", Data: sse.ToolCallData{Tool: name, Args: args}})
		}),
		agent.WithOnToolResult(func(name string, tr *agent.ToolResult) {
			sess.Touch()
			sess.SendEvent(ctx, sse.Event{Type: "tool_result", Data: sse.ToolResultData{
				Tool:    name,
				Success: tr.Success,
				Content: tr.Content,
				Error:   tr.Error,
			}})
		}),
	)

	// Atomically transition to running and enforce global maxConcurrent.
	if err := h.sessions.StartOwned(sess.ID, clientID, cancel); err != nil {
		cancel()
		client.Close()
		var runningErr *session.ErrSessionRunning
		var limitErr *session.ErrMaxConcurrentReached
		var notStartableErr *session.ErrSessionNotStartable
		switch {
		case errors.As(err, &runningErr):
			writeJSON(w, http.StatusConflict, map[string]any{"error": "session already running"})
		case errors.As(err, &notStartableErr):
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		case errors.As(err, &limitErr):
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": err.Error()})
		default:
			writeJSON(w, http.StatusNotFound, map[string]any{"error": "session not found"})
		}
		return
	}

	// Notify Laravel that the session is running
	if h.notifier != nil {
		h.notifier.NotifyWithURL(ctx, sess.CallbackBaseURL, session.StatusPayload{
			SessionID: sess.ID,
			ClientID:  clientID,
			Status:    string(session.StatusRunning),
		})
	}

	go func() {
		defer cancel()
		defer client.Close()
		defer sess.CloseEvents()
		defer tools.CleanupSessionTmp(sess.ID)

		result, err := a.Run(ctx, req.Message)
		if err != nil {
			sess.SetError(err)
			sess.SendEvent(ctx, sse.Event{Type: "error", Data: sse.ErrorData{Message: err.Error()}})
			sess.SendEvent(ctx, sse.Event{Type: "done", Data: sse.DoneData{Status: "failed"}})
			middleware.LogEvent(ctx, "agent_failed", map[string]any{
				"session_id": sess.ID,
				"error":      err.Error(),
			})
			if h.notifier != nil {
				h.notifier.NotifyWithURL(ctx, sess.CallbackBaseURL, session.StatusPayload{
					SessionID: sess.ID,
					ClientID:  clientID,
					Status:    string(session.StatusFailed),
					Error:     err.Error(),
				})
			}
			return
		}

		sess.SetResult(result)
		sess.SendEvent(ctx, sse.Event{Type: "done", Data: sse.DoneData{
			Status:     "completed",
			Output:     result.Text,
			Turns:      result.Turns,
			DurationMs: result.Duration.Milliseconds(),
		}})
		middleware.LogEvent(ctx, "agent_completed", map[string]any{
			"session_id":  sess.ID,
			"turns":       result.Turns,
			"duration_ms": result.Duration.Milliseconds(),
		})
		if h.notifier != nil {
			h.notifier.NotifyWithURL(ctx, sess.CallbackBaseURL, session.StatusPayload{
				SessionID:  sess.ID,
				ClientID:   clientID,
				Status:     string(session.StatusCompleted),
				Output:     result.Text,
				Turns:      result.Turns,
				DurationMs: result.Duration.Milliseconds(),
			})
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]any{
		"session_id":       sess.ID,
		"status":           "running",
		"tools_registered": registered,
	})
}
