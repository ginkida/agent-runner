package middleware

import (
	"context"
	"net"
	"net/http"
)

const ClientIDKey ctxKey = "client_id"

// ClientID extracts client identity from X-Client-ID header.
// Falls back to the remote IP (port stripped) if the header is absent.
func ClientID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Client-ID")
		if id == "" {
			id = extractIP(r.RemoteAddr)
		}
		ctx := context.WithValue(r.Context(), ClientIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// GetClientID extracts the client ID from context.
func GetClientID(ctx context.Context) string {
	if v, ok := ctx.Value(ClientIDKey).(string); ok {
		return v
	}
	return ""
}

func extractIP(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
