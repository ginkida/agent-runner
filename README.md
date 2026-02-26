# Agent Runner

LLM agent microservice for Laravel applications. Runs autonomous AI agents with tool-calling capabilities, streaming results via SSE in real-time.

## Table of Contents

- [Features](#features)
- [Quick Start](#quick-start)
- [How It Works](#how-it-works)
- [Architecture](#architecture)
- [API Reference](#api-reference)
- [Built-in Tools](#built-in-tools)
- [Remote Tools](#remote-tools)
- [HMAC Authentication](#hmac-authentication)
- [SSE Streaming](#sse-streaming)
- [Configuration Reference](#configuration-reference)
- [Deployment](#deployment)
- [Security](#security)
- [Troubleshooting](#troubleshooting)
- [License](#license)

## Features

- **Multi-provider** — OpenAI, Google Gemini, Anthropic Claude. Switch models by changing one string.
- **Built-in tools** — `bash`, `read_file`, `write_file`, `edit_file`, `glob`, `grep`, `list_dir` — sandboxed to a working directory.
- **Remote tools** — Define custom tools in Laravel; Agent Runner calls back via HMAC-signed HTTP.
- **Real-time SSE streaming** — Text, tool calls, and results streamed as they happen.
- **Autonomous agent loop** — The agent decides which tools to call, processes results, and continues until the task is complete.
- **Loop detection** — Automatically detects when an agent is stuck repeating the same action and intervenes.
- **Production-ready** — Circuit breakers, rate limiting, HMAC auth, SSRF protection, graceful shutdown.
- **Minimal dependencies** — Go stdlib + [chi](https://github.com/go-chi/chi) router + YAML parser. No SDKs, no ORMs, no frameworks.

## Quick Start

### Docker (recommended)

```bash
docker run -d \
  -p 8090:8090 \
  -e AGENT_RUNNER_AUTH_HMAC_SECRET=your-secret \
  -e AGENT_RUNNER_PROVIDERS_OPENAI_KEY=sk-... \
  -e AGENT_RUNNER_CALLBACK_BASE_URL=https://your-app.com/api/agent-runner \
  ghcr.io/ginkida/agent-runner:latest
```

### Docker Compose

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your secrets
docker-compose up
```

### From source

```bash
# Build
go build -o agent-runner ./cmd/agent-runner/

# Run
./agent-runner --config config.yaml

# Or with env vars (no config file needed)
AGENT_RUNNER_AUTH_HMAC_SECRET=secret \
AGENT_RUNNER_PROVIDERS_OPENAI_KEY=sk-... \
./agent-runner
```

### Verify it's running

```bash
curl http://localhost:8090/health
# {"status":"ok","active_sessions":0,"total_sessions":0}
```

## How It Works

```
Laravel                          Agent Runner                         LLM Provider
  │                                   │                                    │
  ├─ POST /v1/sessions ──────────────>│  Create session                    │
  │  <── 201 {session_id}             │                                    │
  │                                   │                                    │
  ├─ POST /v1/sessions/{id}/messages ─>│                                   │
  │  <── 202 Accepted                 │                                    │
  │                                   ├─ Send message ───────────────────>│
  │                                   │<─ Stream response ────────────────┤
  │  <── SSE: text chunks             │                                    │
  │                                   │  (agent decides to use tools)      │
  │  <── SSE: tool_call               │                                    │
  │                                   ├─ Execute built-in tool             │
  │  <── SSE: tool_result             │                                    │
  │                                   │  (agent calls remote tool)         │
  │  <── SSE: tool_call               │                                    │
  │  <── POST /tools/{name}           │  (HMAC-signed callback)            │
  │  ──> {success, content}           │                                    │
  │  <── SSE: tool_result             │                                    │
  │                                   ├─ Send results ───────────────────>│
  │                                   │<─ Stream response ────────────────┤
  │  <── SSE: text chunks             │   ... repeat until done ...        │
  │  <── SSE: done                    │                                    │
  │                                   │                                    │
  │  <── POST /sessions/{id}/status   │  (status callback)                 │
  │                                   │                                    │
```

### Lifecycle

1. **Create session** — `POST /v1/sessions` defines the agent: name, model, system prompt, available tools. Returns a `session_id`.
2. **Send message** — `POST /v1/sessions/{id}/messages` with a task for the agent. Returns `202 Accepted` immediately; the agent runs in a background goroutine.
3. **Stream results** — `GET /v1/sessions/{id}/stream` opens an SSE connection. You receive events in real-time as the agent thinks and acts.
4. **Status callbacks** — Agent Runner sends HTTP callbacks to your Laravel app when the session transitions states (`created` → `running` → `completed`/`failed`/`cancelled`).
5. **Cleanup** — Sessions are automatically reaped after the configured TTL (default 30 minutes).

## Architecture

### Agent Loop

Each turn of the agent loop:

1. Send the conversation history to the LLM
2. Stream the response — text is forwarded to SSE in real-time as chunks arrive
3. If the LLM returns tool calls, execute them in parallel (up to 5 concurrent, 2-minute timeout per tool)
4. Append tool results to conversation history
5. Repeat from step 1

The loop stops when:
- The LLM responds with text only (no tool calls) — task complete
- Maximum turns reached (default 30)
- Context timeout expires (default 5 minutes)
- Session is cancelled

### Loop Detection

If the agent calls the same tool with the same arguments 3 times, Agent Runner injects an intervention message:

> LOOP DETECTED: Tool 'read_file' called 3 times with same arguments. Try a different approach.

This prevents infinite loops where the agent gets stuck. The counter resets after intervention, giving the agent a chance to try something different.

### Provider Routing

The model name prefix determines which provider is used:

| Prefix | Provider | Example models |
|--------|----------|----------------|
| `gpt-`, `o1-`, `o3-`, `chatgpt-` | OpenAI | `gpt-4o`, `gpt-4o-mini`, `o3-mini` |
| `gemini-` | Google Gemini | `gemini-2.0-flash`, `gemini-1.5-pro` |
| `claude-` | Anthropic | `claude-sonnet-4-20250514`, `claude-haiku-4-5-20251001` |

No SDKs are used — all providers are called via raw HTTP with streaming response parsing.

### Session States

```
created ──> running ──> completed
                   ├──> failed
                   └──> cancelled (via DELETE)

created ──> (never started, reaped after TTL)
```

### Circuit Breaker

Each provider prefix (`gpt`, `gemini`, `claude`) has a shared circuit breaker:

- **Closed** (normal) — requests flow through; failures are counted
- **Open** (failing) — requests are immediately rejected with `ErrCircuitOpen` after reaching `max_failures` (default 5)
- **Half-Open** (probing) — after `reset_timeout_sec` (default 30s), one request is allowed through as a probe. If it succeeds, the circuit closes; if it fails, it re-opens.

## API Reference

All `/v1/*` endpoints require [HMAC authentication](#hmac-authentication) and an `X-Client-ID` header.

### Health Check

```
GET /health
```

No authentication required. Used for liveness probes.

**Response:**

```json
{
  "status": "ok",
  "active_sessions": 2,
  "total_sessions": 5
}
```

### Create Session

```
POST /v1/sessions
```

Creates a new agent session. The session is in `created` state until a message is sent.

**Request body:**

```json
{
  "session_id": "my-custom-id",
  "work_dir": "/path/to/project",
  "callback": {
    "base_url": "https://my-app.com/api/agent-runner",
    "timeout_sec": 15
  },
  "agent": {
    "name": "code-reviewer",
    "model": "gpt-4o",
    "system_prompt": "You are a senior code reviewer. Be thorough and specific.",
    "max_turns": 10,
    "max_tokens": 4096,
    "temperature": 0.7,
    "tools": {
      "builtin": ["read_file", "write_file", "bash", "glob", "grep"],
      "remote": [
        {
          "name": "search_docs",
          "description": "Search internal documentation",
          "parameters": {
            "type": "object",
            "properties": {
              "query": {"type": "string", "description": "Search query"}
            },
            "required": ["query"]
          }
        }
      ]
    }
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `session_id` | No | Custom session ID (1-128 alphanumeric/dash/underscore). Auto-generated if omitted. |
| `work_dir` | No | Working directory for built-in tools. Must be an absolute path. Defaults to server CWD. |
| `callback.base_url` | No | Override the global callback URL for this session. |
| `callback.timeout_sec` | No | Override the callback timeout for this session. |
| `agent.name` | **Yes** | Agent name (for logging and identification). |
| `agent.model` | No | LLM model to use. Defaults to `defaults.model` from config. |
| `agent.system_prompt` | No | System instruction sent to the LLM. |
| `agent.max_turns` | No | Maximum agent loop iterations. Defaults to `defaults.max_turns`. |
| `agent.max_tokens` | No | Maximum output tokens per LLM call. Defaults to `defaults.max_tokens`. |
| `agent.temperature` | No | LLM temperature (0.0–2.0). |
| `agent.tools.builtin` | No | List of built-in tool names to enable. |
| `agent.tools.remote` | No | List of remote tool definitions with JSON Schema parameters. |

**Response (201):**

```json
{
  "session_id": "a1b2c3d4e5f6",
  "status": "created"
}
```

**Errors:**

| Status | Reason |
|--------|--------|
| 400 | Invalid request body, invalid session_id format, invalid work_dir, invalid callback URL |
| 409 | Session ID already exists |

### Get Session

```
GET /v1/sessions/{id}
```

Returns the current state of a session.

**Response (200):**

```json
{
  "session_id": "a1b2c3d4e5f6",
  "name": "code-reviewer",
  "model": "gpt-4o",
  "status": "completed",
  "output": "I found 3 issues in the codebase...",
  "turns": 5,
  "duration_ms": 12340,
  "created_at": "2026-02-26T12:00:00Z"
}
```

| Field | Description |
|-------|-------------|
| `status` | `created`, `running`, `completed`, `failed`, or `cancelled` |
| `output` | Final text output from the agent (only on `completed`) |
| `error` | Error message (only on `failed`) |
| `turns` | Number of agent loop iterations |
| `duration_ms` | Total execution time in milliseconds |

### Delete Session

```
DELETE /v1/sessions/{id}
```

Cancels a running session and removes it. If the agent is mid-execution, its context is cancelled.

**Response (200):**

```json
{
  "status": "deleted"
}
```

### Send Message

```
POST /v1/sessions/{id}/messages
```

Starts the agent loop with the given message. Returns immediately with `202 Accepted` — the agent runs asynchronously in a background goroutine.

**Request body:**

```json
{
  "message": "Analyze the code in /src and find potential security vulnerabilities"
}
```

**Response (202):**

```json
{
  "session_id": "a1b2c3d4e5f6",
  "status": "running",
  "tools_registered": ["read_file", "glob", "grep", "search_docs"]
}
```

**Errors:**

| Status | Reason |
|--------|--------|
| 400 | Invalid request body or empty message |
| 404 | Session not found or not owned by client |
| 409 | Session is already running |
| 429 | Maximum concurrent running sessions reached |

### Stream Events

```
GET /v1/sessions/{id}/stream
```

Opens a Server-Sent Events (SSE) connection. Events are streamed in real-time as the agent executes. This endpoint has no timeout — the connection stays open until the agent finishes (then the server closes it) or the client disconnects.

See [SSE Streaming](#sse-streaming) for event format details.

## Built-in Tools

All built-in tools are sandboxed to the session's working directory. Symlinks are resolved to prevent directory traversal. Sensitive paths are blocked (`.ssh`, `.aws`, `.kube`, `.docker/config.json`, `/etc/shadow`, `/etc/sudoers`, etc.).

### read_file

Read the contents of a file.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | Yes | Path to the file (relative to work_dir or absolute within work_dir) |
| `offset` | integer | No | 1-based line number to start reading from |
| `limit` | integer | No | Number of lines to read |

- Maximum file size: 10MB
- Output format: numbered lines (`  1\tpackage main`)

### write_file

Create or overwrite a file.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | Yes | Path to the file |
| `content` | string | Yes | File content to write |

- Creates parent directories automatically (mode 0755)
- Files written with mode 0644

### edit_file

Make targeted edits to an existing file.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `file_path` | string | Yes | Path to the file |
| `old_string` | string | Yes | Exact text to find and replace |
| `new_string` | string | Yes | Replacement text |
| `replace_all` | boolean | No | Replace all occurrences (default: false) |

- By default, replaces only the first occurrence
- Errors if `old_string` is not found or appears more than once (unless `replace_all` is true)

### bash

Execute a shell command.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `command` | string | Yes | Shell command to execute |
| `timeout` | integer | No | Timeout in seconds (default: 120) |

**Resource limits (via ulimit):**

| Limit | Value | Purpose |
|-------|-------|---------|
| Max processes (`-u`) | 64 | Fork bomb protection |
| Max file size (`-f`) | 10MB | Prevents filling disk |
| Max virtual memory (`-v`) | 512MB | Prevents OOM |

**Output limits:**
- stdout and stderr are each capped at 100KB
- Truncated output includes a `... (output truncated)` notice

**Blocked commands:**
- Destructive: `rm -rf /`, `mkfs.*`, `dd`, `shutdown`, `reboot`, `halt`
- Fork bombs: `:(){ :|:& };:`
- Network to stdin: `curl|bash`, `wget|sh`, `ssh`, `nc`
- Inline code execution: `python -c`, `ruby -e`, `/dev/tcp`
- Sensitive file access: `chmod 777 /`, raw device writes
- Credential paths: `/.ssh/`, `/.aws/`, `/.config/gcloud/`

**Environment:** Commands run in an isolated environment with minimal PATH, `TERM=dumb`, and a per-session temp directory at `/tmp/agent-runner/{session_id}`.

### glob

Find files by pattern.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern` | string | Yes | Glob pattern (supports `**` for recursive matching) |
| `path` | string | No | Directory to search in (default: work_dir) |

- Supports doublestar patterns: `**/*.go`, `src/**/*.ts`
- Automatically skips: `.git`, `node_modules`, `vendor`, `.idea`
- Maximum 1000 matches returned
- Results are newline-separated absolute paths

### grep

Search file contents by regex.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `pattern` | string | Yes | Regular expression pattern (Go regex syntax) |
| `path` | string | No | File or directory to search (default: work_dir) |
| `include` | string | No | Glob filter for file names (e.g., `*.go`) |

- Full Go regex syntax
- Skips directories: `.git`, `node_modules`, `vendor`, `.idea`, `.vscode`, `__pycache__`
- Skips binary files (>1MB or containing null bytes)
- Maximum 100 matching lines
- Output format: `filepath:linenum:content`

### list_dir

List directory contents.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `path` | string | No | Directory to list (default: work_dir) |

- Output format: `name[/]\tsize` (directories have `/` suffix)

## Remote Tools

Remote tools let you extend the agent with your application's business logic. When the agent calls a remote tool, Agent Runner sends an HMAC-signed HTTP request to your Laravel app.

### How It Works

1. Define the tool in the session creation request with a name, description, and JSON Schema parameters
2. The LLM sees the tool definition and can decide to call it
3. Agent Runner sends a POST to `{callback_base_url}/tools/{tool_name}`
4. Your app processes the request and returns a result
5. The result is passed back to the LLM for the next turn

### Request Format

```
POST {callback_base_url}/tools/{tool_name}
Content-Type: application/json
X-Session-ID: abc123
X-Signature: sha256=<hex_digest>
X-Timestamp: 1709000000
X-Nonce: 4f9a4f1f6d4d7a8f87b5a5c8c2f12a10
```

```json
{
  "session_id": "abc123",
  "tool_name": "search_docs",
  "arguments": {
    "query": "authentication middleware"
  }
}
```

### Response Format

**Success:**

```json
{
  "success": true,
  "content": "Found 3 documents about authentication middleware..."
}
```

**Error:**

```json
{
  "success": false,
  "error": "No documents found for this query"
}
```

### Retry Behavior

- **3 retries** with exponential backoff (1s → 2s → 4s, max 10s, ±20% jitter)
- **5xx responses** — retried automatically
- **4xx responses** — not retried, returned as tool error immediately
- **Network errors** (timeout, connection refused, connection reset, EOF) — retried

### Laravel Example

```php
// routes/api.php
Route::post('agent-runner/tools/{tool}', [AgentToolController::class, 'handle'])
    ->middleware('verify-agent-hmac');

// app/Http/Controllers/AgentToolController.php
class AgentToolController extends Controller
{
    public function handle(Request $request, string $tool)
    {
        return match ($tool) {
            'search_docs' => $this->searchDocs($request->input('arguments')),
            'create_ticket' => $this->createTicket($request->input('arguments')),
            'send_notification' => $this->sendNotification($request->input('arguments')),
            default => response()->json(['success' => false, 'error' => 'Unknown tool'], 404),
        };
    }

    private function searchDocs(array $args): JsonResponse
    {
        $results = Document::search($args['query'])->take(5)->get();

        return response()->json([
            'success' => true,
            'content' => $results->map->summary->implode("\n\n"),
        ]);
    }
}
```

### Status Callbacks

Agent Runner also sends status updates to your app when session state changes:

```
POST {callback_base_url}/sessions/{session_id}/status
```

```json
{
  "session_id": "abc123",
  "client_id": "my-app",
  "status": "completed",
  "output": "Analysis complete. Found 3 issues...",
  "turns": 5,
  "duration_ms": 12340
}
```

Status transitions: `created` → `running` → `completed` / `failed` / `cancelled`

These callbacks are fire-and-forget — they never block the agent. If the callback fails, it's retried up to 3 times, then dropped.

## HMAC Authentication

All `/v1/*` endpoints are authenticated via HMAC-SHA256 signatures. The `/health` endpoint is unauthenticated.

### Signing Requests

Every request must include three headers:

| Header | Value |
|--------|-------|
| `X-Signature` | `sha256=<hex_hmac_digest>` |
| `X-Timestamp` | Unix timestamp (seconds) |
| `X-Nonce` | Unique random string per request |

The signature is computed as:

```
payload = "{timestamp}.{nonce}.{request_body}"
signature = "sha256=" + hex(HMAC-SHA256(payload, secret))
```

For GET/DELETE requests with no body, use an empty string as the request body.

### Replay Protection

- Timestamps must be within **±2 minutes** of the server's clock
- `X-Nonce` must be unique for each request within the freshness window

### PHP Example

```php
function signRequest(string $secret, string $body): array
{
    $timestamp = (string) time();
    $nonce = bin2hex(random_bytes(16));
    $payload = "{$timestamp}.{$nonce}.{$body}";
    $signature = 'sha256=' . hash_hmac('sha256', $payload, $secret);

    return [
        'X-Signature' => $signature,
        'X-Timestamp' => $timestamp,
        'X-Nonce' => $nonce,
    ];
}
```

### JavaScript Example

```javascript
const crypto = require('crypto');

function signRequest(secret, body) {
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const nonce = crypto.randomBytes(16).toString('hex');
  const payload = `${timestamp}.${nonce}.${body}`;
  const signature = 'sha256=' + crypto.createHmac('sha256', secret).update(payload).digest('hex');

  return {
    'X-Signature': signature,
    'X-Timestamp': timestamp,
    'X-Nonce': nonce,
  };
}
```

### Disabling Auth

If `auth.hmac_secret` is empty, authentication is skipped entirely. This is only recommended for local development.

## SSE Streaming

Connect to `GET /v1/sessions/{id}/stream` to receive real-time events. The connection uses standard [Server-Sent Events](https://developer.mozilla.org/en-US/docs/Web/API/Server-Sent_Events/Using_server-sent_events).

### Event Types

#### `text`

Streamed text from the LLM. You'll receive many of these events as the model generates its response token by token.

```
event: text
data: {"content":"Let me analyze "}

event: text
data: {"content":"the code structure..."}
```

#### `tool_call`

The agent has decided to call a tool. Sent before tool execution.

```
event: tool_call
data: {"tool":"read_file","args":{"file_path":"src/main.go"}}
```

#### `tool_result`

A tool has finished executing.

```
event: tool_result
data: {"tool":"read_file","success":true,"content":"package main\n\nimport..."}
```

#### `error`

An error occurred during agent execution.

```
event: error
data: {"message":"context deadline exceeded"}
```

#### `done`

The agent has finished. This is always the last event.

```
event: done
data: {"status":"completed","output":"Found 3 issues...","turns":5,"duration_ms":12340}
```

`status` is either `completed` or `failed`.

### Heartbeat

A heartbeat comment is sent every 30 seconds to keep the connection alive:

```
: heartbeat
```

### Client Example (JavaScript)

```javascript
const eventSource = new EventSource(
  `http://localhost:8090/v1/sessions/${sessionId}/stream`,
  { headers: { 'X-Client-ID': 'my-app', ...signRequest(secret, '') } }
);

eventSource.addEventListener('text', (e) => {
  const { content } = JSON.parse(e.data);
  process.stdout.write(content);
});

eventSource.addEventListener('tool_call', (e) => {
  const { tool, args } = JSON.parse(e.data);
  console.log(`\n[Calling ${tool}]`);
});

eventSource.addEventListener('done', (e) => {
  const { status, turns, duration_ms } = JSON.parse(e.data);
  console.log(`\nDone: ${status} in ${turns} turns (${duration_ms}ms)`);
  eventSource.close();
});

eventSource.addEventListener('error', (e) => {
  const { message } = JSON.parse(e.data);
  console.error('Agent error:', message);
  eventSource.close();
});
```

## Configuration Reference

Configuration is loaded in this order (later overrides earlier):

1. **Built-in defaults**
2. **YAML config file** — path from `--config` flag, or `./config.yaml`, or `~/.config/agent-runner/config.yaml`
3. **Environment variables** — `AGENT_RUNNER_` prefix

### Full Configuration

```yaml
server:
  host: "0.0.0.0"              # Listen address
  port: 8090                    # Listen port (1–65535)
  max_body_bytes: 10485760      # Max request body size (10MB)
  read_header_timeout_sec: 5    # Protect against slowloris headers
  read_timeout_sec: 30          # Max time to read full request
  write_timeout_sec: 65         # Max time to write non-stream responses
  idle_timeout_sec: 120         # Keep-alive idle timeout
  tls:
    cert_file: ""               # TLS certificate path (both or neither)
    key_file: ""                # TLS private key path

auth:
  hmac_secret: ""               # HMAC-SHA256 shared secret (required)

providers:
  openai_key: ""                # OpenAI API key
  gemini_key: ""                # Google Gemini API key
  anthropic_key: ""             # Anthropic API key

defaults:
  model: "gpt-4o-mini"          # Default model when agent doesn't specify
  max_turns: 30                 # Default max agent loop turns
  max_tokens: 4096              # Default max output tokens per LLM call
  timeout_secs: 300             # Default agent timeout in seconds

sessions:
  max_concurrent: 50            # Max simultaneous running sessions (0 = unlimited)
  ttl_minutes: 30               # Minutes before completed sessions are reaped

callback:
  base_url: "http://localhost:8000/api/agent-runner"  # Laravel callback URL
  timeout_sec: 30               # Callback request timeout

rate_limit:
  requests_per_second: 20       # Per-client rate limit
  burst: 40                     # Token bucket burst size

circuit_breaker:
  max_failures: 5               # Failures before circuit opens
  reset_timeout_sec: 30         # Seconds before half-open probe
```

### Environment Variables

Every config value can be overridden via environment variables with the `AGENT_RUNNER_` prefix:

| Variable | Config path | Example |
|----------|------------|---------|
| `AGENT_RUNNER_SERVER_HOST` | `server.host` | `0.0.0.0` |
| `AGENT_RUNNER_SERVER_PORT` | `server.port` | `8090` |
| `AGENT_RUNNER_SERVER_MAX_BODY_BYTES` | `server.max_body_bytes` | `10485760` |
| `AGENT_RUNNER_SERVER_READ_HEADER_TIMEOUT_SEC` | `server.read_header_timeout_sec` | `5` |
| `AGENT_RUNNER_SERVER_READ_TIMEOUT_SEC` | `server.read_timeout_sec` | `30` |
| `AGENT_RUNNER_SERVER_WRITE_TIMEOUT_SEC` | `server.write_timeout_sec` | `65` |
| `AGENT_RUNNER_SERVER_IDLE_TIMEOUT_SEC` | `server.idle_timeout_sec` | `120` |
| `AGENT_RUNNER_TLS_CERT_FILE` | `server.tls.cert_file` | `/etc/ssl/cert.pem` |
| `AGENT_RUNNER_TLS_KEY_FILE` | `server.tls.key_file` | `/etc/ssl/key.pem` |
| `AGENT_RUNNER_AUTH_HMAC_SECRET` | `auth.hmac_secret` | `my-secret` |
| `AGENT_RUNNER_PROVIDERS_OPENAI_KEY` | `providers.openai_key` | `sk-...` |
| `AGENT_RUNNER_PROVIDERS_GEMINI_KEY` | `providers.gemini_key` | `AI...` |
| `AGENT_RUNNER_PROVIDERS_ANTHROPIC_KEY` | `providers.anthropic_key` | `sk-ant-...` |
| `AGENT_RUNNER_DEFAULTS_MODEL` | `defaults.model` | `gpt-4o` |
| `AGENT_RUNNER_DEFAULTS_MAX_TURNS` | `defaults.max_turns` | `30` |
| `AGENT_RUNNER_DEFAULTS_MAX_TOKENS` | `defaults.max_tokens` | `4096` |
| `AGENT_RUNNER_DEFAULTS_TIMEOUT_SECS` | `defaults.timeout_secs` | `300` |
| `AGENT_RUNNER_SESSIONS_MAX_CONCURRENT` | `sessions.max_concurrent` | `50` |
| `AGENT_RUNNER_SESSIONS_TTL_MINUTES` | `sessions.ttl_minutes` | `30` |
| `AGENT_RUNNER_CALLBACK_BASE_URL` | `callback.base_url` | `http://app:8000/api/agent-runner` |
| `AGENT_RUNNER_CALLBACK_TIMEOUT_SEC` | `callback.timeout_sec` | `30` |
| `AGENT_RUNNER_RATELIMIT_RPS` | `rate_limit.requests_per_second` | `20` |
| `AGENT_RUNNER_RATELIMIT_BURST` | `rate_limit.burst` | `40` |
| `AGENT_RUNNER_CB_MAX_FAILURES` | `circuit_breaker.max_failures` | `5` |
| `AGENT_RUNNER_CB_RESET_TIMEOUT_SEC` | `circuit_breaker.reset_timeout_sec` | `30` |

### Docker Secrets

All sensitive variables support a `_FILE` suffix for Docker Swarm secrets:

```bash
AGENT_RUNNER_AUTH_HMAC_SECRET_FILE=/run/secrets/hmac_secret
AGENT_RUNNER_PROVIDERS_OPENAI_KEY_FILE=/run/secrets/openai_key
```

The file content is read and trimmed of whitespace.

### Validation

On startup, the config is validated:

- `auth.hmac_secret` is required
- At least one provider key must be set
- `server.port` must be 1–65535
- `defaults.timeout_secs` must be positive
- `callback.timeout_sec` must not be negative
- `server.read_header_timeout_sec`, `server.read_timeout_sec`, `server.write_timeout_sec`, `server.idle_timeout_sec` must not be negative
- `sessions.max_concurrent` must not be negative (0 = unlimited)
- `sessions.ttl_minutes` must be positive
- TLS: both `cert_file` and `key_file` must be set (or neither), and both files must exist

## Deployment

### Docker Compose (development)

```bash
cp config.example.yaml config.yaml
# Edit config.yaml with your API keys and HMAC secret
docker-compose up -d
```

The `docker-compose.yml` includes:
- Read-only root filesystem
- `no-new-privileges` security option
- tmpfs for temp files (256MB)
- Resource limits (512MB RAM, 1 CPU)
- Log rotation (10MB × 3 files)
- `host.docker.internal` mapping for local Laravel access

### Docker Swarm (production)

```bash
# Create secrets
echo "your-hmac-secret" | docker secret create hmac_secret -
echo "sk-..." | docker secret create openai_key -
echo "" | docker secret create gemini_key -
echo "" | docker secret create anthropic_key -

# Deploy
docker stack deploy -c docker-stack.yml agent-runner
```

The `docker-stack.yml` includes:
- 1 replica (sessions are in-memory)
- Automatic rollback on failure
- Resource limits and reservations
- Health checks
- Overlay network

For multi-replica deployments, you must add sticky routing and an external shared session store; otherwise `messages/get/stream` requests can hit different replicas and return `session not found`.

### Binary

Download pre-built binaries from [Releases](https://github.com/ginkida/agent-runner/releases):

| Platform | Architecture | File |
|----------|-------------|------|
| Linux | x86_64 | `agent-runner-linux-amd64` |
| Linux | ARM64 | `agent-runner-linux-arm64` |
| macOS | x86_64 | `agent-runner-darwin-amd64` |
| macOS | Apple Silicon | `agent-runner-darwin-arm64` |

```bash
chmod +x agent-runner-linux-amd64
./agent-runner-linux-amd64 --config config.yaml
```

### Kubernetes

Use the Docker image with your own manifests or Helm chart:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: agent-runner
spec:
  replicas: 1
  selector:
    matchLabels:
      app: agent-runner
  template:
    metadata:
      labels:
        app: agent-runner
    spec:
      containers:
        - name: agent-runner
          image: ghcr.io/ginkida/agent-runner:latest
          ports:
            - containerPort: 8090
          env:
            - name: AGENT_RUNNER_AUTH_HMAC_SECRET
              valueFrom:
                secretKeyRef:
                  name: agent-runner-secrets
                  key: hmac-secret
            - name: AGENT_RUNNER_PROVIDERS_OPENAI_KEY
              valueFrom:
                secretKeyRef:
                  name: agent-runner-secrets
                  key: openai-key
            - name: AGENT_RUNNER_CALLBACK_BASE_URL
              value: "http://laravel-app:8000/api/agent-runner"
          livenessProbe:
            httpGet:
              path: /health
              port: 8090
            initialDelaySeconds: 5
            periodSeconds: 30
          readinessProbe:
            httpGet:
              path: /health
              port: 8090
            initialDelaySeconds: 3
            periodSeconds: 10
          resources:
            limits:
              memory: 512Mi
              cpu: "1"
            requests:
              memory: 128Mi
              cpu: 250m
          securityContext:
            readOnlyRootFilesystem: true
            runAsNonRoot: true
            allowPrivilegeEscalation: false
          volumeMounts:
            - name: workspace
              mountPath: /workspace
            - name: tmp
              mountPath: /tmp/agent-runner
      volumes:
        - name: workspace
          emptyDir: {}
        - name: tmp
          emptyDir:
            sizeLimit: 256Mi
```

### TLS

To enable TLS, set both certificate and key paths:

```yaml
server:
  tls:
    cert_file: "/etc/ssl/certs/agent-runner.pem"
    key_file: "/etc/ssl/private/agent-runner-key.pem"
```

Or via environment:

```bash
AGENT_RUNNER_TLS_CERT_FILE=/etc/ssl/certs/cert.pem
AGENT_RUNNER_TLS_KEY_FILE=/etc/ssl/private/key.pem
```

### Graceful Shutdown

On SIGINT/SIGTERM, Agent Runner:

1. Stops accepting new connections
2. Cancels all running agents and waits for them to finish
3. Drains SSE connections
4. Shuts down the HTTP server
5. Cleans up background goroutines

The shutdown timeout is `defaults.timeout_secs + 10 seconds` (minimum 10 seconds), giving running agents time to complete before force-stopping.

## Security

### Authentication

- HMAC-SHA256 on all API endpoints (except `/health`)
- Timestamp freshness check (±2 minutes)
- Per-request nonce (`X-Nonce`) blocks replay within the freshness window
- Constant-time signature comparison prevents timing attacks

### Network

- **SSRF protection** — `SafeTransport` resolves DNS at dial time and blocks connections to private IP ranges (10.x, 172.16.x, 192.168.x, 127.x, link-local, loopback)
- **Callback URL validation** — blocks `localhost`, private IPs, and URLs longer than 2000 chars
- **Rate limiting** — per-client token bucket with configurable RPS and burst

### Execution Sandbox

- Built-in tools are sandboxed to the working directory
- Symlinks are resolved to prevent directory traversal
- Sensitive paths are blocked: `/.ssh/`, `/.aws/`, `/.config/gcloud/`, `/.kube/`, `/.docker/config.json`, `/etc/shadow`, `/etc/sudoers`
- Bash commands run with strict ulimit (64 procs, 10MB files, 512MB memory)
- Dangerous commands are blocked by regex (rm -rf, mkfs, fork bombs, curl|bash, etc.)

### Container

- Runs as unprivileged user (`agent`)
- Read-only root filesystem
- `no-new-privileges` flag
- tmpfs for ephemeral temp files

## Troubleshooting

### "missing required config: auth.hmac_secret"

Set the HMAC secret via config or environment:

```bash
export AGENT_RUNNER_AUTH_HMAC_SECRET=your-secret
```

### "missing required config: at least one provider key/url"

Set at least one LLM provider API key:

```bash
export AGENT_RUNNER_PROVIDERS_OPENAI_KEY=sk-...
```

### "max concurrent sessions (N) reached"

Too many sessions are running simultaneously. Either:
- Wait for running sessions to complete
- Increase `sessions.max_concurrent`
- Delete idle sessions via `DELETE /v1/sessions/{id}`

### "circuit breaker is open"

The LLM provider has failed too many times. The circuit breaker will automatically attempt a probe after `reset_timeout_sec` (default 30s). Check:
- Provider API key is valid
- Provider service is reachable
- Rate limits haven't been exceeded on the provider side

### SSE stream hangs after agent completes

The SSE connection closes when the client disconnects after receiving the `done` event. If your client isn't closing the connection, handle the `done` event:

```javascript
eventSource.addEventListener('done', () => eventSource.close());
```

### "connection to private IP X is blocked"

Agent Runner blocks SSRF attempts. If your callback URL legitimately resolves to a private IP (e.g., internal service), you need to configure networking so the callback uses a public or routable address. In Docker, use `host.docker.internal` to reach the host machine.

### Tool result truncated

Tool outputs are capped at 100KB. If you need larger outputs, consider:
- Using `offset` and `limit` parameters for `read_file`
- Filtering output in bash commands with `head`, `tail`, or `grep`
- Splitting work across multiple tool calls

## License

[MIT](LICENSE)
