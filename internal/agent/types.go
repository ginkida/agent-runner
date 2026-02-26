package agent

// SchemaType represents JSON Schema types.
type SchemaType string

const (
	TypeString  SchemaType = "string"
	TypeInteger SchemaType = "integer"
	TypeNumber  SchemaType = "number"
	TypeBoolean SchemaType = "boolean"
	TypeArray   SchemaType = "array"
	TypeObject  SchemaType = "object"
)

// Schema describes the parameters for a tool (JSON Schema subset).
type Schema struct {
	Type        SchemaType         `json:"type"`
	Description string             `json:"description,omitempty"`
	Properties  map[string]*Schema `json:"properties,omitempty"`
	Required    []string           `json:"required,omitempty"`
	Items       *Schema            `json:"items,omitempty"`
	Enum        []string           `json:"enum,omitempty"`
}

// FunctionDeclaration describes a tool available to the model.
type FunctionDeclaration struct {
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Parameters  *Schema `json:"parameters"`
}

// FunctionCall represents the model requesting a tool execution.
type FunctionCall struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

// FunctionResponse represents the result of a tool execution sent back to the model.
type FunctionResponse struct {
	ID       string         `json:"id"`
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

// Content represents a message in the conversation history.
type Content struct {
	Role  string `json:"role"` // "user", "model", "system"
	Parts []Part `json:"parts"`
}

// Part is a component of a Content message.
type Part struct {
	Text             string            `json:"text,omitempty"`
	FunctionCall     *FunctionCall     `json:"function_call,omitempty"`
	FunctionResponse *FunctionResponse `json:"function_response,omitempty"`
}

// NewTextContent creates a Content with a single text part.
func NewTextContent(role, text string) *Content {
	return &Content{
		Role:  role,
		Parts: []Part{{Text: text}},
	}
}

// FinishReason indicates why the model stopped generating.
type FinishReason string

const (
	FinishReasonStop      FinishReason = "stop"
	FinishReasonMaxTokens FinishReason = "max_tokens"
)
