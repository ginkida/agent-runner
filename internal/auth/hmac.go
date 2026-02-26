package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxTimestampAge = 2 * time.Minute

// HMACMiddleware returns middleware that verifies HMAC-SHA256 signatures.
// Expects headers:
//
//	X-Signature: sha256=<hex digest>
//	X-Timestamp: <unix seconds>
//
// The signed payload is: timestamp + "." + request body
func HMACMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret == "" {
				next.ServeHTTP(w, r)
				return
			}

			sig := r.Header.Get("X-Signature")
			ts := r.Header.Get("X-Timestamp")

			if sig == "" || ts == "" {
				http.Error(w, `{"error":"missing signature or timestamp"}`, http.StatusUnauthorized)
				return
			}

			// Verify timestamp freshness
			tsInt, err := strconv.ParseInt(ts, 10, 64)
			if err != nil {
				http.Error(w, `{"error":"invalid timestamp"}`, http.StatusUnauthorized)
				return
			}
			age := time.Since(time.Unix(tsInt, 0))
			if age < 0 {
				age = -age
			}
			if age > maxTimestampAge {
				http.Error(w, `{"error":"timestamp too old"}`, http.StatusUnauthorized)
				return
			}

			// Read and buffer body
			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, `{"error":"failed to read body"}`, http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			// Compute expected signature
			payload := ts + "." + string(body)
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(payload))
			expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

			if !hmac.Equal([]byte(sig), []byte(expected)) {
				http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SignRequest signs a request body with HMAC-SHA256, returning the signature and timestamp.
func SignRequest(secret string, body []byte) (signature, timestamp string) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	payload := ts + "." + string(body)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	return sig, ts
}

// StripPrefix removes the "sha256=" prefix from a signature string.
func StripPrefix(sig string) string {
	return strings.TrimPrefix(sig, "sha256=")
}
