# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Agent Runner is a Go microservice that bridges Laravel applications with LLM providers (OpenAI, Gemini, Anthropic). It runs autonomous AI agents that execute tasks through a turn-based tool-calling loop, with both built-in tools (file operations, bash, glob, grep) and remote tools (HTTP callbacks to Laravel). Communication is real-time via SSE streaming.

## Build & Run Commands

```bash
# Build
go build -o dist/agent-runner ./cmd/agent-runner/

# Build with version
go build -ldflags="-s -w -X main.version=1.0.0" -o dist/agent-runner ./cmd/agent-runner/

# Run tests
go test -race ./...

# Vet
go vet ./...

# Docker build
docker build --build-arg VERSION=dev -t agent-runner:dev .

# Local development
docker-compose up
```

## Architecture

### Request Flow

```
Laravel POST /v1/sessions → create session
Laravel POST /v1/sessions/{id}/messages → starts agent goroutine
  Agent goroutine: LLM → stream response → execute tools → send results → repeat
  SSE events sent to session.Events channel in real-time
Client GET /v1/sessions/{id}/stream → reads SSE events
Laravel receives status callbacks (fire-and-forget) on state transitions
```

### Core Agent Loop (`internal/agent/agent.go`)

Turn-based loop: send message to LLM → stream response → if function calls present, execute tools in parallel (max 5 concurrent, 2min per tool) → send results back → repeat until no more tool calls or max turns reached (default 30). Loop detection interrupts when the same tool+args combination repeats 3+ times.

Streaming callbacks (`OnText`, `OnToolCall`, `OnToolResult`) fire in real-time as chunks arrive from the LLM, enabling live SSE output.

### Key Interfaces

- **`agent.Client`** (`internal/agent/client.go`) — LLM provider abstraction with streaming. Returns `*StreamResponse` with a `Chunks` channel. Implementations in `internal/provider/{openai,gemini,anthropic}/`.
- **`agent.Tool`** (`internal/agent/tool.go`) — Tool interface: `Execute(ctx, args map[string]any) (*ToolResult, error)`. All tools implement this.
- **`agent.Registry`** (`internal/agent/tool.go`) — Thread-safe tool registry (RWMutex). Manages declarations sent to the LLM.

### Provider Routing (`internal/provider/factory.go`)

Model name prefix determines provider:

| Prefix | Provider |
|--------|----------|
| `gpt-`, `o1-`, `o3-`, `chatgpt-` | OpenAI |
| `gemini-` | Google Gemini |
| `claude-` | Anthropic |

Each provider gets a shared circuit breaker (per provider prefix, stored in `sync.Map` registry). Providers use stdlib `net/http` — no SDKs.

### Session Management (`internal/session/`)

**Session lifecycle:** `created` → `running` → `completed`/`failed`/`cancelled`

- `Events` channel: buffered (64), used for SSE streaming
- `eventsDone` channel: signals no more events (CloseEvents does NOT close Events channel — prevents send-on-closed panic)
- `TryStart()`: atomic CAS to prevent double-start TOCTOU
- `SendEvent()`: non-blocking with 5s timeout, respects eventsDone signal

**Manager:** In-memory store with RWMutex. Enforces per-client ownership, concurrent session limits. Cleanup goroutine runs every 60s, reaps terminal sessions and abandoned `created` sessions older than TTL.

**StatusNotifier:** Fire-and-forget callbacks to Laravel on state transitions. Semaphore-bounded (32 goroutines), drops excess with logging. HMAC-signed. Retries 3x with backoff on 5xx.

### HTTP Layer (`internal/server/routes.go`)

Routes use chi/v5. Middleware chain:

```
Global:  RequestID → StructuredLogger → Recoverer → BodyLimit(10MB)
/v1/*:   HMACAuth → ClientID → RateLimiter(20rps, burst 40, 60s timeout)
/health: no auth, no rate limit
```

```
GET    /health                     — liveness probe (no auth)
POST   /v1/sessions                — create session
GET    /v1/sessions/{id}           — get session info
DELETE /v1/sessions/{id}           — cancel & delete session
POST   /v1/sessions/{id}/messages  — run agent (returns 202, spawns goroutine)
GET    /v1/sessions/{id}/stream    — SSE stream (no timeout)
```

### Built-in Tools (`internal/tools/builtin.go`)

All sandboxed to `workDir` with symlink resolution. Sensitive paths blocked (`/.ssh/`, `/.aws/`, `/etc/shadow`, etc.).

| Tool | Key params | Limits |
|------|-----------|--------|
| `read_file` | `file_path`, `offset`, `limit` | 10MB max file size |
| `write_file` | `file_path`, `content` | Creates parent dirs (0755) |
| `edit_file` | `file_path`, `old_string`, `new_string`, `replace_all` | Unique match required unless replace_all |
| `bash` | `command`, `timeout` (default 120s) | ulimit: 64 procs, 10MB files, 512MB vmem. 100KB output cap. Dangerous command blocklist (rm -rf, curl\|bash, fork bombs, etc.) |
| `glob` | `pattern`, `path` | Doublestar support. Skips .git/node_modules/vendor. Max 1000 matches |
| `grep` | `pattern`, `path`, `include` | Go regex. Skips binary files (>1MB or null bytes). Max 100 results |
| `list_dir` | `path` | Returns `name[/]\tsize` |

### Remote Tools (`internal/tools/remote.go`)

Delegate execution to Laravel via `POST {baseURL}/tools/{toolName}`. HMAC-signed requests (`X-Signature`, `X-Timestamp`). Expects JSON response: `{"success": true, "content": "..."}` or `{"success": false, "error": "..."}`. Retries 3x with exponential backoff on 5xx. Uses `SafeTransport` (SSRF protection).

### Resilience (`internal/resilience/`)

**Circuit breaker:** Closed → Open (after N failures) → HalfOpen (one probe after timeout) → Closed. Shared per provider prefix via `sync.Map` registry. Default: 5 failures, 30s reset.

**Retry:** Exponential backoff with ±20% jitter. Formula: `min(base * 2^attempt, maxDelay)`.

### Security

- **HMAC auth** (`internal/auth/`): `sha256=HMAC(timestamp.body, secret)`. ±2min timestamp freshness. Constant-time comparison.
- **SSRF protection** (`internal/netutil/`): `SafeTransport` resolves DNS at dial time, blocks private IPs (RFC1918, loopback, link-local). Guards against DNS rebinding.
- **Bash sandboxing**: Dangerous command regex blocklist, ulimit resource caps, isolated PATH/env.
- **Session isolation**: All operations verify `clientID` ownership.

## Configuration

YAML config with env variable overrides using `AGENT_RUNNER_` prefix. Supports `_FILE` suffix for Docker secrets (e.g., `AGENT_RUNNER_AUTH_HMAC_SECRET_FILE` reads from file path).

**Loading order:** defaults → YAML file → env overrides

**Key env vars:**
```
AGENT_RUNNER_SERVER_PORT=8090
AGENT_RUNNER_AUTH_HMAC_SECRET=<secret>
AGENT_RUNNER_PROVIDERS_OPENAI_KEY=<key>
AGENT_RUNNER_PROVIDERS_GEMINI_KEY=<key>
AGENT_RUNNER_PROVIDERS_ANTHROPIC_KEY=<key>
AGENT_RUNNER_DEFAULTS_MODEL=gpt-4o-mini
AGENT_RUNNER_DEFAULTS_TIMEOUT_SECS=300
AGENT_RUNNER_SESSIONS_MAX_CONCURRENT=50
AGENT_RUNNER_SESSIONS_TTL_MINUTES=30
AGENT_RUNNER_CALLBACK_BASE_URL=http://localhost:8000/api/agent-runner
```

See `config.example.yaml` for all options.

**Validation:** port 1–65535, positive timeouts, non-negative session limits, TLS both-or-neither with file existence check.

## Graceful Shutdown (`cmd/agent-runner/main.go`)

1. Receive SIGINT/SIGTERM
2. Compute shutdown timeout: `max(timeout_secs + 10s, 10s)`
3. `sessions.Drain(ctx)` — cancel all running agents, poll until done
4. `httpServer.Shutdown(ctx)` — stop accepting, finish in-flight
5. `rateLimiter.Stop()` + `sessions.Stop()` — cleanup goroutines

## Dependencies

Minimal — two external packages:
- `go-chi/chi/v5` — HTTP router + middleware
- `gopkg.in/yaml.v3` — config parsing

Everything else is stdlib. No ORMs, no SDKs, no frameworks.

## Conventions

- Functional options pattern for constructors (`WithTemperature`, `WithMaxTurns`, etc.)
- Mutex protection on all shared state (session, registry, circuit breaker, manager)
- Context-first function signatures throughout
- Error wrapping with `%w` for context chains, `errors.As()` for type checks
- Tool result content truncated at 100KB (`MaxToolResultBytes`)
- Helper functions `GetString`, `GetInt`, `GetBool` (+ `Default` variants) for typed arg extraction from `map[string]any`
- JSON structured logging via `middleware.LogEvent(ctx, event, fields)`
- No test files currently exist — all packages show `[no test files]`

## File Map

```
cmd/agent-runner/main.go          — entrypoint, signal handling, graceful shutdown
internal/
  agent/
    agent.go                      — core agent loop, streaming, loop detection
    client.go                     — Client interface, StreamResponse, Content types
    tool.go                       — Tool interface, Registry, ToolResult, arg helpers
    executor.go                   — parallel tool execution (max 5 concurrent, 2min timeout)
  config/config.go                — config loading, env overrides, validation
  provider/
    factory.go                    — model prefix → provider routing
    openai/openai.go              — OpenAI Chat Completions streaming
    gemini/gemini.go              — Gemini REST API streaming
    anthropic/anthropic.go        — Anthropic Messages API streaming
  session/
    session.go                    — session state, events channel, lifecycle
    manager.go                    — in-memory store, cleanup, drain
    notifier.go                   — fire-and-forget status callbacks to Laravel
  server/
    server.go                     — HTTP server with TLS support
    routes.go                     — route registration, middleware stack
  handler/
    session.go                    — create/get/delete session handlers
    message.go                    — POST messages handler, agent goroutine spawn
    stream.go                     — SSE stream handler
    health.go                     — health check endpoint
  tools/
    builtin.go                    — 7 built-in tools with sandboxing
    remote.go                     — remote tool HTTP delegation
    registry.go                   — BuildRegistry from AgentDefinition
  middleware/
    request_id.go                 — X-Request-ID generation/propagation
    logger.go                     — JSON structured access logging
    body_limit.go                 — request body size limit
    client_id.go                  — X-Client-ID extraction
    ratelimit.go                  — per-client token bucket rate limiter
  auth/hmac.go                    — HMAC signing & verification middleware
  resilience/
    circuitbreaker.go             — circuit breaker with shared registry
    retry.go                      — exponential backoff with jitter
  netutil/ssrf.go                 — SafeTransport, private IP blocking
  sse/writer.go                   — SSE event types, Stream() writer
```
