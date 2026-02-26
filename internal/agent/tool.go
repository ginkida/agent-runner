package agent

import (
	"context"
	"fmt"
	"sync"
)

// Tool defines the interface for all tools available to the agent.
type Tool interface {
	Name() string
	Description() string
	Declaration() *FunctionDeclaration
	Execute(ctx context.Context, args map[string]any) (*ToolResult, error)
}

// MaxToolResultBytes is the maximum size for tool result content (100KB).
const MaxToolResultBytes = 100 * 1024

// ToolResult represents the result of a tool execution.
type ToolResult struct {
	Content string
	Error   string
	Success bool
}

// NewSuccessResult creates a successful tool result.
// Content exceeding MaxToolResultBytes is truncated.
func NewSuccessResult(content string) *ToolResult {
	if len(content) > MaxToolResultBytes {
		content = content[:MaxToolResultBytes] + fmt.Sprintf("\n... (truncated: showing %d of %d bytes)", MaxToolResultBytes, len(content))
	}
	return &ToolResult{Content: content, Success: true}
}

// NewErrorResult creates a failed tool result.
func NewErrorResult(errMsg string) *ToolResult {
	return &ToolResult{Error: errMsg, Success: false}
}

// ToMap converts the result to a map for function response payloads.
func (r *ToolResult) ToMap() map[string]any {
	result := make(map[string]any)
	if r.Success {
		result["success"] = true
		if r.Content != "" {
			result["content"] = r.Content
		}
	} else {
		result["success"] = false
		result["error"] = r.Error
	}
	return result
}

// Registry manages available tools.
type Registry struct {
	tools map[string]Tool
	mu    sync.RWMutex
}

// NewRegistry creates an empty tool registry.
func NewRegistry() *Registry {
	return &Registry{tools: make(map[string]Tool)}
}

// Register adds a tool to the registry.
func (r *Registry) Register(tool Tool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := tool.Name()
	if _, exists := r.tools[name]; exists {
		return fmt.Errorf("tool already registered: %s", name)
	}
	r.tools[name] = tool
	return nil
}

// Get retrieves a tool by name.
func (r *Registry) Get(name string) (Tool, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tool, ok := r.tools[name]
	return tool, ok
}

// List returns all registered tools.
func (r *Registry) List() []Tool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	tools := make([]Tool, 0, len(r.tools))
	for _, t := range r.tools {
		tools = append(tools, t)
	}
	return tools
}

// Names returns the names of all registered tools.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.tools))
	for name := range r.tools {
		names = append(names, name)
	}
	return names
}

// Declarations returns all tool declarations for passing to the LLM.
func (r *Registry) Declarations() []*FunctionDeclaration {
	r.mu.RLock()
	defer r.mu.RUnlock()
	decls := make([]*FunctionDeclaration, 0, len(r.tools))
	for _, t := range r.tools {
		decls = append(decls, t.Declaration())
	}
	return decls
}

// GetString extracts a string argument from the args map.
func GetString(args map[string]any, key string) (string, bool) {
	val, ok := args[key]
	if !ok {
		return "", false
	}
	str, ok := val.(string)
	return str, ok
}

// GetStringDefault extracts a string argument with a default value.
func GetStringDefault(args map[string]any, key, defaultVal string) string {
	if val, ok := GetString(args, key); ok {
		return val
	}
	return defaultVal
}

// GetInt extracts an integer argument from the args map.
func GetInt(args map[string]any, key string) (int, bool) {
	val, ok := args[key]
	if !ok {
		return 0, false
	}
	switch v := val.(type) {
	case int:
		return v, true
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	}
	return 0, false
}

// GetIntDefault extracts an integer argument with a default value.
func GetIntDefault(args map[string]any, key string, defaultVal int) int {
	if val, ok := GetInt(args, key); ok {
		return val
	}
	return defaultVal
}

// GetBool extracts a boolean argument from the args map.
func GetBool(args map[string]any, key string) (bool, bool) {
	val, ok := args[key]
	if !ok {
		return false, false
	}
	b, ok := val.(bool)
	return b, ok
}

// GetBoolDefault extracts a boolean argument with a default value.
func GetBoolDefault(args map[string]any, key string, defaultVal bool) bool {
	if val, ok := GetBool(args, key); ok {
		return val
	}
	return defaultVal
}
