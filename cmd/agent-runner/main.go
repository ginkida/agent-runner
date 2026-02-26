package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/ginkida/agent-runner/internal/config"
	"github.com/ginkida/agent-runner/internal/server"
	"github.com/ginkida/agent-runner/internal/session"
)

var version = "dev"

func main() {
	configPath := flag.String("config", "", "Path to config.yaml")
	showVersion := flag.Bool("version", false, "Print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println("agent-runner", version)
		os.Exit(0)
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if err := cfg.Validate(); err != nil {
		log.Fatalf("Invalid config: %v", err)
	}

	sessions := session.NewManager(cfg.Sessions.MaxConcurrent, cfg.Sessions.TTLMinutes)

	// Create status notifier for Laravel callbacks (nil-safe — handlers check for nil)
	var notifier *session.StatusNotifier
	if cfg.Callback.BaseURL != "" {
		notifier = session.NewStatusNotifier(cfg.Callback.BaseURL, cfg.Auth.HMACSecret, cfg.Callback.TimeoutSec)
	}

	srv := server.New(cfg, sessions, notifier)

	// Graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-stop

	shutdownTimeout := time.Duration(cfg.Defaults.TimeoutSecs)*time.Second + 10*time.Second
	if shutdownTimeout < 10*time.Second {
		shutdownTimeout = 10 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Shutdown error: %v", err)
	}

	log.Println("Server stopped")
}
