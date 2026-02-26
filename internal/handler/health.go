package handler

import (
	"encoding/json"
	"net/http"

	"github.com/ginkida/agent-runner/internal/session"
)

// HealthHandler serves the health check endpoint.
type HealthHandler struct {
	sessions *session.Manager
}

// NewHealthHandler creates a new health handler.
func NewHealthHandler(sessions *session.Manager) *HealthHandler {
	return &HealthHandler{sessions: sessions}
}

// Handle responds with server health status.
func (h *HealthHandler) Handle(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"status":          "ok",
		"active_sessions": h.sessions.ActiveCount(),
		"total_sessions":  h.sessions.Count(),
	})
}
