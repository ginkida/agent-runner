package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"time"
)

// ErrSessionExists is returned when a requested session ID is already in use.
type ErrSessionExists struct{ ID string }

func (e *ErrSessionExists) Error() string {
	return fmt.Sprintf("session %q already exists", e.ID)
}

// ErrSessionNotFound is returned when a session does not exist (or is not owned by caller).
type ErrSessionNotFound struct{ ID string }

func (e *ErrSessionNotFound) Error() string {
	return fmt.Sprintf("session %q not found", e.ID)
}

// ErrSessionRunning is returned when trying to start an already running session.
type ErrSessionRunning struct{ ID string }

func (e *ErrSessionRunning) Error() string {
	return fmt.Sprintf("session %q already running", e.ID)
}

// ErrSessionNotStartable is returned when trying to start a session that is not in the created state.
type ErrSessionNotStartable struct {
	ID     string
	Status string
}

func (e *ErrSessionNotStartable) Error() string {
	return fmt.Sprintf("session %q cannot be started (status: %s)", e.ID, e.Status)
}

// ErrMaxConcurrentReached is returned when max running sessions limit is reached.
type ErrMaxConcurrentReached struct{ Limit int }

func (e *ErrMaxConcurrentReached) Error() string {
	return fmt.Sprintf("max concurrent sessions (%d) reached", e.Limit)
}

// Manager is an in-memory session store with TTL-based cleanup.
type Manager struct {
	sessions      map[string]*Session
	mu            sync.RWMutex
	maxConcurrent int
	ttl           time.Duration
	stopCleanup   chan struct{}
}

// NewManager creates a session manager and starts the cleanup goroutine.
func NewManager(maxConcurrent int, ttlMinutes int) *Manager {
	m := &Manager{
		sessions:      make(map[string]*Session),
		maxConcurrent: maxConcurrent,
		ttl:           time.Duration(ttlMinutes) * time.Minute,
		stopCleanup:   make(chan struct{}),
	}
	go m.cleanupLoop()
	return m
}

// Create creates a new session from the given agent definition, owned by clientID.
// If requestedID is non-empty it is used as the session ID (must be unique);
// otherwise a random ID is generated.
func (m *Manager) Create(clientID, requestedID string, def AgentDefinition, opts SessionOptions) (*Session, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Resolve session ID
	id := requestedID
	if id == "" {
		id = generateID()
	} else if _, exists := m.sessions[id]; exists {
		return nil, &ErrSessionExists{ID: id}
	}

	sess := NewSession(id, clientID, def, opts)
	m.sessions[id] = sess
	return sess, nil
}

// StartOwned atomically transitions a session to running while enforcing maxConcurrent.
// cancelFn is stored only when the transition succeeds.
func (m *Manager) StartOwned(id, clientID string, cancelFn func()) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[id]
	if !ok || sess.ClientID != clientID {
		return &ErrSessionNotFound{ID: id}
	}

	status := sess.GetStatus()
	if status == StatusRunning {
		return &ErrSessionRunning{ID: id}
	}
	if status != StatusCreated {
		return &ErrSessionNotStartable{ID: id, Status: string(status)}
	}

	if m.maxConcurrent > 0 && m.runningCountLocked() >= m.maxConcurrent {
		return &ErrMaxConcurrentReached{Limit: m.maxConcurrent}
	}

	if !sess.TryStart() {
		return &ErrSessionRunning{ID: id}
	}
	sess.SetCancel(cancelFn)

	return nil
}

// Get retrieves a session by ID.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessions[id]
	return sess, ok
}

// GetOwned retrieves a session only if it belongs to the given clientID.
func (m *Manager) GetOwned(id, clientID string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sess, ok := m.sessions[id]
	if !ok || sess.ClientID != clientID {
		return nil, false
	}
	return sess, true
}

// DeleteOwned cancels and removes a session only if it belongs to the given clientID.
func (m *Manager) DeleteOwned(id, clientID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[id]
	if !ok || sess.ClientID != clientID {
		return false
	}

	sess.CancelIfRunning()
	sess.CloseEvents()
	sess.SetStatus(StatusCancelled)
	delete(m.sessions, id)
	return true
}

// Delete cancels and removes a session.
func (m *Manager) Delete(id string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	sess, ok := m.sessions[id]
	if !ok {
		return false
	}

	sess.CancelIfRunning()
	sess.CloseEvents()
	sess.SetStatus(StatusCancelled)
	delete(m.sessions, id)
	return true
}

// Count returns the total number of sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.sessions)
}

// ActiveCount returns the number of running sessions.
func (m *Manager) ActiveCount() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.runningCountLocked()
}

// Drain cancels all running agents and waits for them to finish.
// This unblocks SSE streams so httpServer.Shutdown can complete.
func (m *Manager) Drain(ctx context.Context) error {
	m.mu.RLock()
	var running []*Session
	for _, sess := range m.sessions {
		if sess.GetStatus() == StatusRunning {
			running = append(running, sess)
		}
	}
	m.mu.RUnlock()

	if len(running) == 0 {
		return nil
	}

	log.Printf("Draining %d running session(s)...", len(running))
	for _, sess := range running {
		sess.CancelIfRunning()
	}

	// Poll until all done or context deadline
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if m.ActiveCount() == 0 {
				return nil
			}
		}
	}
}

// Stop stops the cleanup goroutine.
func (m *Manager) Stop() {
	close(m.stopCleanup)
}

func (m *Manager) cleanupLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			m.reapExpired()
		case <-m.stopCleanup:
			return
		}
	}
}

func (m *Manager) reapExpired() {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	for id, sess := range m.sessions {
		sess.mu.RLock()
		status := sess.Status
		completedAt := sess.CompletedAt
		createdAt := sess.CreatedAt
		sess.mu.RUnlock()

		// Reap terminal sessions that have exceeded TTL since completion.
		isTerminal := status == StatusCompleted || status == StatusFailed || status == StatusCancelled
		if isTerminal && !completedAt.IsZero() && now.Sub(completedAt) > m.ttl {
			sess.CloseEvents()
			delete(m.sessions, id)
			continue
		}

		// Reap created-but-never-started sessions older than TTL to prevent memory leaks.
		if status == StatusCreated && now.Sub(createdAt) > m.ttl {
			sess.CloseEvents()
			delete(m.sessions, id)
		}
	}
}

func generateID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (m *Manager) runningCountLocked() int {
	count := 0
	for _, s := range m.sessions {
		if s.GetStatus() == StatusRunning {
			count++
		}
	}
	return count
}
