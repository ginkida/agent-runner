package resilience

import (
	"errors"
	"sync"
	"time"
)

// ErrCircuitOpen is returned when the circuit breaker is open and rejecting calls.
var ErrCircuitOpen = errors.New("circuit breaker is open")

// State represents the circuit breaker state.
type State int

const (
	StateClosed   State = iota // normal operation
	StateOpen                  // fast-failing
	StateHalfOpen              // probing with a single call
)

// CircuitBreaker implements the circuit breaker pattern for provider calls.
type CircuitBreaker struct {
	name            string
	maxFailures     int
	resetTimeout    time.Duration
	state           State
	failures        int
	lastFailureTime time.Time
	mu              sync.Mutex
}

// NewCircuitBreaker creates a new circuit breaker.
func NewCircuitBreaker(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	if maxFailures <= 0 {
		maxFailures = 5
	}
	if resetTimeout <= 0 {
		resetTimeout = 30 * time.Second
	}
	return &CircuitBreaker{
		name:         name,
		maxFailures:  maxFailures,
		resetTimeout: resetTimeout,
		state:        StateClosed,
	}
}

// Execute runs fn through the circuit breaker.
// Returns ErrCircuitOpen if the circuit is open and the reset timeout hasn't elapsed.
func (cb *CircuitBreaker) Execute(fn func() error) error {
	cb.mu.Lock()
	switch cb.state {
	case StateOpen:
		if time.Since(cb.lastFailureTime) >= cb.resetTimeout {
			// Transition to half-open: allow one probe call
			cb.state = StateHalfOpen
			cb.mu.Unlock()
		} else {
			cb.mu.Unlock()
			return ErrCircuitOpen
		}
	case StateHalfOpen:
		// Already probing — reject additional calls while probe is in-flight.
		cb.mu.Unlock()
		return ErrCircuitOpen
	default:
		cb.mu.Unlock()
	}

	err := fn()

	cb.mu.Lock()
	defer cb.mu.Unlock()

	if err != nil {
		cb.failures++
		cb.lastFailureTime = time.Now()
		if cb.state == StateHalfOpen {
			// Probe failed — back to open
			cb.state = StateOpen
		} else if cb.failures >= cb.maxFailures {
			cb.state = StateOpen
		}
		return err
	}

	// Success — reset
	cb.failures = 0
	cb.state = StateClosed
	return nil
}

// GetState returns the current circuit breaker state (for monitoring).
func (cb *CircuitBreaker) GetState() State {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return cb.state
}

// registry holds shared circuit breaker instances keyed by name.
var registry sync.Map

// GetOrCreateCircuitBreaker returns an existing circuit breaker for the given
// name or creates a new one. This ensures CB state (failures, state) is shared
// across calls instead of being reset on every NewClient invocation.
func GetOrCreateCircuitBreaker(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	if v, ok := registry.Load(name); ok {
		return v.(*CircuitBreaker)
	}
	cb := NewCircuitBreaker(name, maxFailures, resetTimeout)
	actual, _ := registry.LoadOrStore(name, cb)
	return actual.(*CircuitBreaker)
}
