package middleware

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"time"

	chimw "github.com/go-chi/chi/v5/middleware"
)

// StructuredLogger is a chi middleware that outputs JSON-structured access logs.
func StructuredLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ww := chimw.NewWrapResponseWriter(w, r.ProtoMajor)

		next.ServeHTTP(ww, r)

		fields := map[string]any{
			"ts":         start.Format(time.RFC3339),
			"request_id": GetRequestID(r.Context()),
			"client_id":  GetClientID(r.Context()),
			"method":     r.Method,
			"path":       r.URL.Path,
			"status":     ww.Status(),
			"bytes":      ww.BytesWritten(),
			"latency_ms": time.Since(start).Milliseconds(),
			"remote":     r.RemoteAddr,
		}
		data, _ := json.Marshal(fields)
		log.Println(string(data))
	})
}

// LogEvent writes a structured JSON log line with request_id and client_id from context.
func LogEvent(ctx context.Context, event string, fields map[string]any) {
	if fields == nil {
		fields = make(map[string]any)
	}
	fields["request_id"] = GetRequestID(ctx)
	fields["client_id"] = GetClientID(ctx)
	fields["event"] = event
	fields["ts"] = time.Now().Format(time.RFC3339)
	data, _ := json.Marshal(fields)
	log.Println(string(data))
}
