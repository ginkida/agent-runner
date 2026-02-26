package auth

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxTimestampAge = 2 * time.Minute

var nonceStore = newReplayNonceStore(2 * maxTimestampAge)

// HMACMiddleware returns middleware that verifies HMAC-SHA256 signatures.
// Expects headers:
//
//	X-Signature: sha256=<hex digest>
//	X-Timestamp: <unix seconds>
//	X-Nonce: <random nonce>
//
// The signed payload is: timestamp + "." + nonce + "." + request body
func HMACMiddleware(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if secret == "" {
				next.ServeHTTP(w, r)
				return
			}

			sig := r.Header.Get("X-Signature")
			ts := r.Header.Get("X-Timestamp")
			nonce := r.Header.Get("X-Nonce")

			if sig == "" || ts == "" || nonce == "" {
				http.Error(w, `{"error":"missing signature, timestamp, or nonce"}`, http.StatusUnauthorized)
				return
			}
			if !isValidNonce(nonce) {
				http.Error(w, `{"error":"invalid nonce"}`, http.StatusUnauthorized)
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
			payload := ts + "." + nonce + "." + string(body)
			mac := hmac.New(sha256.New, []byte(secret))
			mac.Write([]byte(payload))
			expected := "sha256=" + hex.EncodeToString(mac.Sum(nil))

			if !hmac.Equal([]byte(sig), []byte(expected)) {
				http.Error(w, `{"error":"invalid signature"}`, http.StatusUnauthorized)
				return
			}
			if !nonceStore.MarkIfNew(nonce, time.Now()) {
				http.Error(w, `{"error":"replayed request"}`, http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// SignRequest signs a request body with HMAC-SHA256 and returns signature, timestamp, and nonce.
func SignRequest(secret string, body []byte) (signature, timestamp, nonce string) {
	ts := fmt.Sprintf("%d", time.Now().Unix())
	nonce = generateNonce()
	payload := ts + "." + nonce + "." + string(body)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := "sha256=" + hex.EncodeToString(mac.Sum(nil))

	return sig, ts, nonce
}

// StripPrefix removes the "sha256=" prefix from a signature string.
func StripPrefix(sig string) string {
	return strings.TrimPrefix(sig, "sha256=")
}

type replayNonceStore struct {
	mu       sync.Mutex
	seen     map[string]time.Time
	ttl      time.Duration
	lastReap time.Time
}

func newReplayNonceStore(ttl time.Duration) *replayNonceStore {
	return &replayNonceStore{
		seen: make(map[string]time.Time),
		ttl:  ttl,
	}
}

// MarkIfNew returns true for first-seen nonces, false for replayed nonce values.
func (s *replayNonceStore) MarkIfNew(nonce string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Reap at most once per 30 seconds to avoid O(n) scan on every request.
	if now.Sub(s.lastReap) > 30*time.Second {
		s.reapLocked(now)
		s.lastReap = now
	}
	if _, exists := s.seen[nonce]; exists {
		return false
	}
	s.seen[nonce] = now
	return true
}

func (s *replayNonceStore) reapLocked(now time.Time) {
	cutoff := now.Add(-s.ttl)
	for nonce, ts := range s.seen {
		if ts.Before(cutoff) {
			delete(s.seen, nonce)
		}
	}
}

func generateNonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func isValidNonce(nonce string) bool {
	if len(nonce) < 8 || len(nonce) > 128 {
		return false
	}
	for i := 0; i < len(nonce); i++ {
		ch := nonce[i]
		isLetter := (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z')
		isDigit := ch >= '0' && ch <= '9'
		if !isLetter && !isDigit && ch != '_' && ch != '-' {
			return false
		}
	}
	return true
}
