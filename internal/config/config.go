package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server         ServerConfig         `yaml:"server"`
	Auth           AuthConfig           `yaml:"auth"`
	Providers      ProvidersConfig      `yaml:"providers"`
	Defaults       DefaultsConfig       `yaml:"defaults"`
	Sessions       SessionsConfig       `yaml:"sessions"`
	Callback       CallbackConfig       `yaml:"callback"`
	RateLimit      RateLimitConfig      `yaml:"rate_limit"`
	CircuitBreaker CircuitBreakerConfig `yaml:"circuit_breaker"`
}

type CircuitBreakerConfig struct {
	MaxFailures     int `yaml:"max_failures"`
	ResetTimeoutSec int `yaml:"reset_timeout_sec"`
}

type ServerConfig struct {
	Host         string    `yaml:"host"`
	Port         int       `yaml:"port"`
	MaxBodyBytes int64     `yaml:"max_body_bytes"`
	TLS          TLSConfig `yaml:"tls"`
}

// TLSConfig holds TLS certificate paths. Both fields must be set to enable TLS.
type TLSConfig struct {
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

// Enabled returns true if both cert and key files are configured.
func (t TLSConfig) Enabled() bool {
	return t.CertFile != "" && t.KeyFile != ""
}

type AuthConfig struct {
	HMACSecret string `yaml:"hmac_secret"`
}

type ProvidersConfig struct {
	OpenAIKey    string `yaml:"openai_key"`
	GeminiKey    string `yaml:"gemini_key"`
	AnthropicKey string `yaml:"anthropic_key"`
}

type DefaultsConfig struct {
	Model       string `yaml:"model"`
	MaxTurns    int    `yaml:"max_turns"`
	MaxTokens   int32  `yaml:"max_tokens"`
	TimeoutSecs int    `yaml:"timeout_secs"`
}

type SessionsConfig struct {
	MaxConcurrent int `yaml:"max_concurrent"`
	TTLMinutes    int `yaml:"ttl_minutes"`
}

type CallbackConfig struct {
	BaseURL    string `yaml:"base_url"`
	TimeoutSec int    `yaml:"timeout_sec"`
}

type RateLimitConfig struct {
	RequestsPerSecond float64 `yaml:"requests_per_second"`
	Burst             int     `yaml:"burst"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Host:         "0.0.0.0",
			Port:         8090,
			MaxBodyBytes: 10 * 1024 * 1024, // 10MB
		},
		Defaults: DefaultsConfig{
			Model:       "gpt-4o-mini",
			MaxTurns:    30,
			MaxTokens:   4096,
			TimeoutSecs: 300,
		},
		Sessions: SessionsConfig{
			MaxConcurrent: 50,
			TTLMinutes:    30,
		},
		Callback: CallbackConfig{
			BaseURL:    "http://localhost:8000/api/agent-runner",
			TimeoutSec: 30,
		},
		Providers: ProvidersConfig{},
		RateLimit: RateLimitConfig{
			RequestsPerSecond: 20,
			Burst:             40,
		},
		CircuitBreaker: CircuitBreakerConfig{
			MaxFailures:     5,
			ResetTimeoutSec: 30,
		},
	}
}

// Load reads config from the given path, falling back to default locations.
// Environment variables override YAML values.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()

	paths := []string{path}
	if path == "" {
		paths = []string{
			"./config.yaml",
			filepath.Join(homeDir(), ".config", "agent-runner", "config.yaml"),
		}
	}

	var loaded bool
	for _, p := range paths {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config %s: %w", p, err)
		}
		loaded = true
		break
	}

	if !loaded && path != "" {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	applyEnvOverrides(cfg)
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("AGENT_RUNNER_SERVER_HOST"); v != "" {
		cfg.Server.Host = v
	}
	if v := os.Getenv("AGENT_RUNNER_SERVER_PORT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = n
		}
	}
	if v := os.Getenv("AGENT_RUNNER_SERVER_MAX_BODY_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.Server.MaxBodyBytes = n
		}
	}
	if v := os.Getenv("AGENT_RUNNER_TLS_CERT_FILE"); v != "" {
		cfg.Server.TLS.CertFile = v
	}
	if v := os.Getenv("AGENT_RUNNER_TLS_KEY_FILE"); v != "" {
		cfg.Server.TLS.KeyFile = v
	}
	if v := envOrFile("AGENT_RUNNER_AUTH_HMAC_SECRET"); v != "" {
		cfg.Auth.HMACSecret = v
	}
	if v := envOrFile("AGENT_RUNNER_PROVIDERS_OPENAI_KEY"); v != "" {
		cfg.Providers.OpenAIKey = v
	}
	if v := envOrFile("AGENT_RUNNER_PROVIDERS_GEMINI_KEY"); v != "" {
		cfg.Providers.GeminiKey = v
	}
	if v := envOrFile("AGENT_RUNNER_PROVIDERS_ANTHROPIC_KEY"); v != "" {
		cfg.Providers.AnthropicKey = v
	}
	if v := os.Getenv("AGENT_RUNNER_DEFAULTS_MODEL"); v != "" {
		cfg.Defaults.Model = v
	}
	if v := os.Getenv("AGENT_RUNNER_DEFAULTS_MAX_TURNS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Defaults.MaxTurns = n
		}
	}
	if v := os.Getenv("AGENT_RUNNER_DEFAULTS_TIMEOUT_SECS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Defaults.TimeoutSecs = n
		}
	}
	if v := os.Getenv("AGENT_RUNNER_DEFAULTS_MAX_TOKENS"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 32); err == nil {
			cfg.Defaults.MaxTokens = int32(n)
		}
	}
	if v := os.Getenv("AGENT_RUNNER_SESSIONS_MAX_CONCURRENT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Sessions.MaxConcurrent = n
		}
	}
	if v := os.Getenv("AGENT_RUNNER_SESSIONS_TTL_MINUTES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Sessions.TTLMinutes = n
		}
	}
	if v := os.Getenv("AGENT_RUNNER_CALLBACK_BASE_URL"); v != "" {
		cfg.Callback.BaseURL = v
	}
	if v := os.Getenv("AGENT_RUNNER_CALLBACK_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Callback.TimeoutSec = n
		}
	}
	if v := os.Getenv("AGENT_RUNNER_RATELIMIT_RPS"); v != "" {
		if n, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.RateLimit.RequestsPerSecond = n
		}
	}
	if v := os.Getenv("AGENT_RUNNER_RATELIMIT_BURST"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.RateLimit.Burst = n
		}
	}
	if v := os.Getenv("AGENT_RUNNER_CB_MAX_FAILURES"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CircuitBreaker.MaxFailures = n
		}
	}
	if v := os.Getenv("AGENT_RUNNER_CB_RESET_TIMEOUT_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.CircuitBreaker.ResetTimeoutSec = n
		}
	}
}

// Addr returns the listen address string.
func (c *Config) Addr() string {
	return fmt.Sprintf("%s:%d", c.Server.Host, c.Server.Port)
}

func homeDir() string {
	home, _ := os.UserHomeDir()
	return home
}

// envOrFile returns the value of envKey, or reads from the file at envKey+"_FILE".
// This supports Docker Swarm secrets mounted at /run/secrets/<name>.
func envOrFile(envKey string) string {
	if v := os.Getenv(envKey); v != "" {
		return v
	}
	if path := os.Getenv(envKey + "_FILE"); path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			return strings.TrimSpace(string(data))
		}
	}
	return ""
}

// Validate checks required configuration.
func (c *Config) Validate() error {
	var missing []string
	if c.Auth.HMACSecret == "" {
		missing = append(missing, "auth.hmac_secret")
	}
	// At least one provider key should be set
	if c.Providers.OpenAIKey == "" && c.Providers.GeminiKey == "" &&
		c.Providers.AnthropicKey == "" {
		missing = append(missing, "at least one provider key/url")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required config: %s", strings.Join(missing, ", "))
	}

	// Port range
	if c.Server.Port < 1 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535, got %d", c.Server.Port)
	}

	// Timeout values
	if c.Defaults.TimeoutSecs <= 0 {
		return fmt.Errorf("defaults.timeout_secs must be positive, got %d", c.Defaults.TimeoutSecs)
	}
	if c.Callback.TimeoutSec < 0 {
		return fmt.Errorf("callback.timeout_sec must not be negative, got %d", c.Callback.TimeoutSec)
	}

	// Session limits
	if c.Sessions.MaxConcurrent < 0 {
		return fmt.Errorf("sessions.max_concurrent must not be negative, got %d", c.Sessions.MaxConcurrent)
	}
	if c.Sessions.TTLMinutes <= 0 {
		return fmt.Errorf("sessions.ttl_minutes must be positive, got %d", c.Sessions.TTLMinutes)
	}

	// TLS: both or neither
	tls := c.Server.TLS
	if (tls.CertFile == "") != (tls.KeyFile == "") {
		return fmt.Errorf("tls: both cert_file and key_file must be set, or neither")
	}
	if tls.Enabled() {
		if _, err := os.Stat(tls.CertFile); err != nil {
			return fmt.Errorf("tls cert_file not readable: %w", err)
		}
		if _, err := os.Stat(tls.KeyFile); err != nil {
			return fmt.Errorf("tls key_file not readable: %w", err)
		}
	}

	return nil
}
