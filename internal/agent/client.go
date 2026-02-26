package agent

import "context"

// Client defines the interface for LLM provider communication.
type Client interface {
	// SendMessage sends a single message and returns a streaming response.
	SendMessage(ctx context.Context, message string) (*StreamResponse, error)

	// SendMessageWithHistory sends a message with full conversation history.
	SendMessageWithHistory(ctx context.Context, history []*Content, message string) (*StreamResponse, error)

	// SendFunctionResponse sends tool execution results back to the model.
	SendFunctionResponse(ctx context.Context, history []*Content, results []*FunctionResponse) (*StreamResponse, error)

	// SetTools sets the tools available for the model to call.
	SetTools(tools []*FunctionDeclaration)

	// SetSystemInstruction sets the system prompt.
	SetSystemInstruction(instruction string)

	// GetModel returns the model identifier.
	GetModel() string

	// Close releases any resources.
	Close() error
}
