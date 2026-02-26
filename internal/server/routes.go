package server

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"

	"github.com/ginkida/agent-runner/internal/auth"
	"github.com/ginkida/agent-runner/internal/config"
	"github.com/ginkida/agent-runner/internal/handler"
	mw "github.com/ginkida/agent-runner/internal/middleware"
	"github.com/ginkida/agent-runner/internal/session"
)

// NewRouter creates the chi router with all routes registered.
func NewRouter(cfg *config.Config, sessions *session.Manager, rateLimiter *mw.RateLimiter, notifier *session.StatusNotifier) http.Handler {
	r := chi.NewRouter()

	// Global middleware (order matters)
	r.Use(mw.RequestID)                          // 1. assign request ID
	r.Use(mw.StructuredLogger)                   // 2. structured JSON logging
	r.Use(chimw.Recoverer)                       // 3. panic recovery
	r.Use(mw.BodyLimit(cfg.Server.MaxBodyBytes)) // 4. body size limit

	// Handlers
	healthH := handler.NewHealthHandler(sessions)
	sessionH := handler.NewSessionHandler(sessions, notifier)
	messageH := handler.NewMessageHandler(sessions, cfg, notifier)
	streamH := handler.NewStreamHandler(sessions)

	// Health endpoint (no auth)
	r.Get("/health", healthH.Handle)

	// API v1 routes (with HMAC auth)
	r.Route("/v1", func(r chi.Router) {
		r.Use(auth.HMACMiddleware(cfg.Auth.HMACSecret)) // 5. HMAC auth
		r.Use(mw.ClientID)                               // 6. extract client ID (after HMAC validates)
		r.Use(rateLimiter.Middleware())                   // 7. rate limit per client

		// API routes — 60s timeout
		r.Group(func(r chi.Router) {
			r.Use(chimw.Timeout(60 * time.Second))
			r.Post("/sessions", sessionH.Create)
			r.Get("/sessions/{id}", sessionH.Get)
			r.Delete("/sessions/{id}", sessionH.Delete)
			r.Post("/sessions/{id}/messages", messageH.Send)
		})

		// SSE stream — no timeout, heartbeat keeps alive
		r.Get("/sessions/{id}/stream", streamH.Stream)
	})

	return r
}
