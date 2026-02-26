package provider

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/ginkida/agent-runner/internal/agent"
	"github.com/ginkida/agent-runner/internal/config"
	"github.com/ginkida/agent-runner/internal/provider/anthropic"
	"github.com/ginkida/agent-runner/internal/provider/gemini"
	openaiProvider "github.com/ginkida/agent-runner/internal/provider/openai"
	"github.com/ginkida/agent-runner/internal/resilience"
)

// NewClient creates an agent.Client based on the model name.
// If temperature is non-nil, it is passed to the provider.
// If maxTokens > 0, it overrides the provider's default max output tokens.
func NewClient(model string, cfg *config.ProvidersConfig, cbCfg *config.CircuitBreakerConfig, temperature *float32, maxTokens int32) (agent.Client, error) {
	if temperature != nil {
		t := float64(*temperature)
		if math.IsNaN(t) || math.IsInf(t, 0) || t < 0 || t > 2 {
			return nil, fmt.Errorf("temperature must be between 0 and 2, got %f", t)
		}
	}

	cb := buildCircuitBreaker(model, cbCfg)

	switch {
	case isOpenAIModel(model):
		if cfg.OpenAIKey == "" {
			return nil, fmt.Errorf("OpenAI API key not configured for model %s", model)
		}
		var opts []openaiProvider.Option
		if temperature != nil {
			opts = append(opts, openaiProvider.WithTemperature(*temperature))
		}
		if maxTokens > 0 {
			opts = append(opts, openaiProvider.WithMaxTokens(maxTokens))
		}
		opts = append(opts, openaiProvider.WithCircuitBreaker(cb))
		return openaiProvider.New(cfg.OpenAIKey, model, opts...)

	case strings.HasPrefix(model, "gemini-"):
		if cfg.GeminiKey == "" {
			return nil, fmt.Errorf("Gemini API key not configured for model %s", model)
		}
		var opts []gemini.Option
		if temperature != nil {
			opts = append(opts, gemini.WithTemperature(*temperature))
		}
		if maxTokens > 0 {
			opts = append(opts, gemini.WithMaxTokens(maxTokens))
		}
		opts = append(opts, gemini.WithCircuitBreaker(cb))
		return gemini.New(cfg.GeminiKey, model, opts...)

	case strings.HasPrefix(model, "claude-"):
		if cfg.AnthropicKey == "" {
			return nil, fmt.Errorf("Anthropic API key not configured for model %s", model)
		}
		var opts []anthropic.Option
		if temperature != nil {
			opts = append(opts, anthropic.WithTemperature(*temperature))
		}
		if maxTokens > 0 {
			opts = append(opts, anthropic.WithMaxTokens(maxTokens))
		}
		opts = append(opts, anthropic.WithCircuitBreaker(cb))
		return anthropic.New(cfg.AnthropicKey, model, opts...)

	default:
		return nil, fmt.Errorf("unsupported model %q: expected prefix gpt-/o1-/o3-/chatgpt- (OpenAI), gemini- (Gemini), or claude- (Anthropic)", model)
	}
}

func buildCircuitBreaker(model string, cbCfg *config.CircuitBreakerConfig) *resilience.CircuitBreaker {
	maxFailures := 5
	resetTimeout := 30 * time.Second
	if cbCfg != nil {
		if cbCfg.MaxFailures > 0 {
			maxFailures = cbCfg.MaxFailures
		}
		if cbCfg.ResetTimeoutSec > 0 {
			resetTimeout = time.Duration(cbCfg.ResetTimeoutSec) * time.Second
		}
	}
	// Use the model prefix as the CB name for shared state per provider
	name := model
	if i := strings.Index(model, "-"); i > 0 {
		name = model[:i]
	}
	return resilience.GetOrCreateCircuitBreaker(name, maxFailures, resetTimeout)
}

func isOpenAIModel(model string) bool {
	for _, p := range []string{"gpt-", "o1-", "o3-", "chatgpt-"} {
		if strings.HasPrefix(model, p) {
			return true
		}
	}
	return false
}
