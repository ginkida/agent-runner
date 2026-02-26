package handler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/ginkida/agent-runner/internal/middleware"
	"github.com/ginkida/agent-runner/internal/netutil"
	"github.com/ginkida/agent-runner/internal/session"
)

// SessionHandler manages session CRUD operations.
type SessionHandler struct {
	sessions *session.Manager
	notifier *session.StatusNotifier
}

// NewSessionHandler creates a new session handler.
func NewSessionHandler(sessions *session.Manager, notifier *session.StatusNotifier) *SessionHandler {
	return &SessionHandler{sessions: sessions, notifier: notifier}
}

// callbackOverride allows per-session callback configuration.
type callbackOverride struct {
	BaseURL    string `json:"base_url"`
	TimeoutSec int    `json:"timeout_sec,omitempty"`
}

// createRequest is the JSON body for POST /v1/sessions.
type createRequest struct {
	SessionID string                  `json:"session_id,omitempty"`
	WorkDir   string                  `json:"work_dir,omitempty"`
	Callback  *callbackOverride       `json:"callback,omitempty"`
	Agent     session.AgentDefinition `json:"agent"`
}

// Create handles POST /v1/sessions.
func (h *SessionHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "invalid request body: " + err.Error(),
		})
		return
	}

	if req.Agent.Name == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error": "agent.name is required",
		})
		return
	}

	// Validate optional fields
	if req.SessionID != "" {
		if err := validateSessionID(req.SessionID); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid session_id: " + err.Error(),
			})
			return
		}
	}
	if req.WorkDir != "" {
		if err := validateWorkDir(req.WorkDir); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid work_dir: " + err.Error(),
			})
			return
		}
	}
	if req.Callback != nil && req.Callback.BaseURL != "" {
		if err := validateCallbackURL(req.Callback.BaseURL); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error": "invalid callback.base_url: " + err.Error(),
			})
			return
		}
	}

	// Build session options
	opts := session.SessionOptions{WorkDir: req.WorkDir}
	if req.Callback != nil {
		opts.CallbackBaseURL = req.Callback.BaseURL
		opts.CallbackTimeout = req.Callback.TimeoutSec
	}

	clientID := middleware.GetClientID(r.Context())
	sess, err := h.sessions.Create(clientID, req.SessionID, req.Agent, opts)
	if err != nil {
		var existsErr *session.ErrSessionExists
		if errors.As(err, &existsErr) {
			writeJSON(w, http.StatusConflict, map[string]any{"error": err.Error()})
		} else {
			writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": err.Error()})
		}
		return
	}

	if h.notifier != nil {
		h.notifier.NotifyWithURL(context.Background(), sess.CallbackBaseURL, session.StatusPayload{
			SessionID: sess.ID,
			ClientID:  clientID,
			Status:    string(session.StatusCreated),
		})
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"session_id": sess.ID,
		"status":     string(sess.GetStatus()),
	})
}

// Get handles GET /v1/sessions/{id}.
func (h *SessionHandler) Get(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	clientID := middleware.GetClientID(r.Context())
	sess, ok := h.sessions.GetOwned(id, clientID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "session not found",
		})
		return
	}

	writeJSON(w, http.StatusOK, sess.Info())
}

// Delete handles DELETE /v1/sessions/{id}.
func (h *SessionHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	clientID := middleware.GetClientID(r.Context())

	// Capture callback URL before deletion
	var callbackURL string
	if sess, ok := h.sessions.GetOwned(id, clientID); ok {
		callbackURL = sess.CallbackBaseURL
	}

	if !h.sessions.DeleteOwned(id, clientID) {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "session not found",
		})
		return
	}

	if h.notifier != nil {
		h.notifier.NotifyWithURL(context.Background(), callbackURL, session.StatusPayload{
			SessionID: id,
			ClientID:  clientID,
			Status:    string(session.StatusCancelled),
		})
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "deleted",
	})
}

var validSessionID = regexp.MustCompile(`^[a-zA-Z0-9_\-]{1,128}$`)

func validateSessionID(id string) error {
	if !validSessionID.MatchString(id) {
		return fmt.Errorf("must be 1-128 alphanumeric/dash/underscore characters")
	}
	return nil
}

func validateWorkDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("must be an absolute path")
	}
	info, err := os.Stat(filepath.Clean(dir))
	if err != nil {
		return fmt.Errorf("not accessible: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("not a directory")
	}
	return nil
}

func validateCallbackURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("scheme must be http or https")
	}
	hostname := u.Hostname()
	if hostname == "" {
		return fmt.Errorf("host is required")
	}
	if strings.EqualFold(hostname, "localhost") {
		return fmt.Errorf("localhost callbacks are not allowed")
	}
	if ip := net.ParseIP(hostname); ip != nil && netutil.IsPrivateIP(ip) {
		return fmt.Errorf("private IP callbacks are not allowed")
	}
	if len(rawURL) > 2000 {
		return fmt.Errorf("callback URL too long")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
