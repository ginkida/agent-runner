package server

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"

	"github.com/ginkida/agent-runner/internal/config"
	"github.com/ginkida/agent-runner/internal/middleware"
	"github.com/ginkida/agent-runner/internal/session"
)

// Server wraps the HTTP server with graceful shutdown.
type Server struct {
	httpServer  *http.Server
	cfg         *config.Config
	sessions    *session.Manager
	rateLimiter *middleware.RateLimiter
}

// New creates a new Server.
func New(cfg *config.Config, sessions *session.Manager, notifier *session.StatusNotifier) *Server {
	rl := middleware.NewRateLimiter(cfg.RateLimit.RequestsPerSecond, cfg.RateLimit.Burst)
	router := NewRouter(cfg, sessions, rl, notifier)

	srv := &http.Server{
		Addr:    cfg.Addr(),
		Handler: router,
	}

	if cfg.Server.TLS.Enabled() {
		srv.TLSConfig = &tls.Config{
			MinVersion: tls.VersionTLS12,
		}
	}

	return &Server{
		httpServer:  srv,
		cfg:         cfg,
		sessions:    sessions,
		rateLimiter: rl,
	}
}

// ListenAndServe starts the HTTP server (TLS if configured, plaintext otherwise).
func (s *Server) ListenAndServe() error {
	if s.cfg.Server.TLS.Enabled() {
		log.Printf("Agent Runner listening on %s (TLS)", s.httpServer.Addr)
		return s.httpServer.ListenAndServeTLS(
			s.cfg.Server.TLS.CertFile,
			s.cfg.Server.TLS.KeyFile,
		)
	}
	log.Printf("Agent Runner listening on %s", s.httpServer.Addr)
	return s.httpServer.ListenAndServe()
}

// Shutdown gracefully shuts down the server.
// Order: drain agents → stop HTTP → cleanup goroutines.
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("Shutting down server...")
	// 1. Drain running agents → closes SSE channels → unblocks in-flight streams
	if err := s.sessions.Drain(ctx); err != nil {
		log.Printf("Drain warning: %v", err)
	}
	// 2. Stop HTTP (now safe — streams already closed)
	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.Printf("HTTP shutdown warning: %v", err)
	}
	// 3. Cleanup goroutines
	s.rateLimiter.Stop()
	s.sessions.Stop()
	return nil
}
