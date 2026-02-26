package agent

import "context"

// StreamResponse represents a streaming response from an LLM.
type StreamResponse struct {
	Chunks <-chan ResponseChunk
	Done   <-chan struct{}
}

// ResponseChunk is a single piece of a streaming response.
type ResponseChunk struct {
	Text          string
	FunctionCalls []*FunctionCall
	Error         error
	Done          bool
	FinishReason  FinishReason
	InputTokens   int
	OutputTokens  int
}

// Response is the fully collected result of a streaming response.
type Response struct {
	Text          string
	FunctionCalls []*FunctionCall
	FinishReason  FinishReason
	InputTokens   int
	OutputTokens  int
}

// Collect reads all chunks from a StreamResponse into a single Response.
func (sr *StreamResponse) Collect(ctx context.Context) (*Response, error) {
	resp := &Response{}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case chunk, ok := <-sr.Chunks:
			if !ok {
				return resp, nil
			}
			if chunk.Error != nil {
				return nil, chunk.Error
			}

			resp.Text += chunk.Text
			resp.FunctionCalls = append(resp.FunctionCalls, chunk.FunctionCalls...)

			if chunk.InputTokens > 0 {
				resp.InputTokens = chunk.InputTokens
			}
			if chunk.OutputTokens > 0 {
				resp.OutputTokens += chunk.OutputTokens
			}

			if chunk.Done {
				resp.FinishReason = chunk.FinishReason
				return resp, nil
			}
		}
	}
}
