package middleware

import "net/http"

// BodyLimit returns middleware that limits the request body size.
// Uses http.MaxBytesReader so the server returns 413 on overflow.
func BodyLimit(maxBytes int64) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			next.ServeHTTP(w, r)
		})
	}
}
