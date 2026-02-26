package handler

import (
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/ginkida/agent-runner/internal/middleware"
	"github.com/ginkida/agent-runner/internal/session"
	"github.com/ginkida/agent-runner/internal/sse"
)

// StreamHandler serves SSE streams for sessions.
type StreamHandler struct {
	sessions *session.Manager
}

// NewStreamHandler creates a new stream handler.
func NewStreamHandler(sessions *session.Manager) *StreamHandler {
	return &StreamHandler{sessions: sessions}
}

// Stream handles GET /v1/sessions/{id}/stream.
func (h *StreamHandler) Stream(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	clientID := middleware.GetClientID(r.Context())
	sess, ok := h.sessions.GetOwned(id, clientID)
	if !ok {
		writeJSON(w, http.StatusNotFound, map[string]any{
			"error": "session not found",
		})
		return
	}

	sess.Touch()
	sse.Stream(w, r, sess.Events, sess.EventsDone())
}
