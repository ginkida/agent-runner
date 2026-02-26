package tools

import (
	"fmt"
	"strings"

	"github.com/ginkida/agent-runner/internal/agent"
	"github.com/ginkida/agent-runner/internal/session"
)

// BuildRegistry creates a combined registry with builtin and remote tools.
func BuildRegistry(agentDef session.AgentDefinition, callbackBaseURL, hmacSecret, sessionID, workDir string, callbackTimeoutSec int) (*agent.Registry, []string, error) {
	registry := agent.NewRegistry()
	var registered []string

	for _, name := range agentDef.Tools.Builtin {
		factory, ok := Builtins[name]
		if !ok {
			return nil, nil, fmt.Errorf("unknown builtin tool: %s", name)
		}
		tool := factory(workDir, sessionID)
		if err := registry.Register(tool); err != nil {
			return nil, nil, fmt.Errorf("register builtin %s: %w", name, err)
		}
		registered = append(registered, name)
	}

	for _, def := range agentDef.Tools.Remote {
		schema := convertJSONSchema(def.Parameters)
		tool, err := NewRemoteTool(RemoteToolConfig{
			Name:            def.Name,
			Description:     def.Description,
			Schema:          schema,
			CallbackBaseURL: callbackBaseURL,
			HMACSecret:      hmacSecret,
			SessionID:       sessionID,
			TimeoutSec:      callbackTimeoutSec,
		})
		if err != nil {
			return nil, nil, fmt.Errorf("create remote tool %s: %w", def.Name, err)
		}
		if err := registry.Register(tool); err != nil {
			return nil, nil, fmt.Errorf("register remote %s: %w", def.Name, err)
		}
		registered = append(registered, def.Name)
	}

	return registry, registered, nil
}

// convertJSONSchema converts a JSON Schema map to an agent.Schema.
func convertJSONSchema(params map[string]any) *agent.Schema {
	if params == nil {
		return &agent.Schema{
			Type:       agent.TypeObject,
			Properties: map[string]*agent.Schema{},
		}
	}

	schema := &agent.Schema{}

	if t, ok := params["type"].(string); ok {
		schema.Type = mapSchemaType(t)
	} else {
		schema.Type = agent.TypeObject
	}

	if desc, ok := params["description"].(string); ok {
		schema.Description = desc
	}

	if enum, ok := params["enum"].([]any); ok {
		for _, e := range enum {
			if s, ok := e.(string); ok {
				schema.Enum = append(schema.Enum, s)
			}
		}
	}

	if props, ok := params["properties"].(map[string]any); ok {
		schema.Properties = make(map[string]*agent.Schema)
		for name, propDef := range props {
			if propMap, ok := propDef.(map[string]any); ok {
				schema.Properties[name] = convertJSONSchema(propMap)
			}
		}
	}

	if required, ok := params["required"].([]any); ok {
		for _, r := range required {
			if s, ok := r.(string); ok {
				schema.Required = append(schema.Required, s)
			}
		}
	}

	if items, ok := params["items"].(map[string]any); ok {
		schema.Items = convertJSONSchema(items)
	}

	return schema
}

func mapSchemaType(t string) agent.SchemaType {
	switch strings.ToLower(t) {
	case "string":
		return agent.TypeString
	case "integer":
		return agent.TypeInteger
	case "number":
		return agent.TypeNumber
	case "boolean":
		return agent.TypeBoolean
	case "array":
		return agent.TypeArray
	case "object":
		return agent.TypeObject
	default:
		return agent.TypeString
	}
}
