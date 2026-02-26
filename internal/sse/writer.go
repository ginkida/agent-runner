package sse

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Event represents a Server-Sent Event.
type Event struct {
	Type string `json:"type"` // text, tool_call, tool_result, thinking, error, done
	Data any    `json:"data"` // JSON-serializable payload
}

// TextData is the payload for text events.
type TextData struct {
	Content string `json:"content"`
}

// ToolCallData is the payload for tool_call events.
type ToolCallData struct {
	Tool string         `json:"tool"`
	Args map[string]any `json:"args"`
}

// ToolResultData is the payload for tool_result events.
type ToolResultData struct {
	Tool    string `json:"tool"`
	Success bool   `json:"success"`
	Content string `json:"content"`
}

// DoneData is the payload for done events.
type DoneData struct {
	Status     string `json:"status"`
	Output     string `json:"output,omitempty"`
	Turns      int    `json:"turns,omitempty"`
	DurationMs int64  `json:"duration_ms,omitempty"`
}

// ErrorData is the payload for error events.
type ErrorData struct {
	Message string `json:"message"`
}

// Stream writes SSE events from a channel to an http.ResponseWriter.
// It blocks until the channel is closed or the client disconnects.
func Stream(w http.ResponseWriter, r *http.Request, events <-chan Event, done <-chan struct{}) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}
	// Keep SSE connection exempt from server WriteTimeout.
	_ = http.NewResponseController(w).SetWriteDeadline(time.Time{})

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	heartbeat := time.NewTicker(30 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case <-r.Context().Done():
			return
		case <-done:
			return
		case <-heartbeat.C:
			if _, err := fmt.Fprintf(w, ": heartbeat\n\n"); err != nil {
				return // client gone
			}
			flusher.Flush()
		case event, ok := <-events:
			if !ok {
				// Channel closed, send final empty data
				return
			}

			data, err := json.Marshal(event.Data)
			if err != nil {
				errData, _ := json.Marshal(map[string]string{"error": "marshal failed: " + err.Error()})
				data = errData
			}

			if _, err := fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event.Type, string(data)); err != nil {
				return // client gone
			}
			flusher.Flush()
		}
	}
}

// WriteEvent writes a single SSE event directly.
func WriteEvent(w http.ResponseWriter, eventType string, data any) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return
	}

	fmt.Fprintf(w, "event: %s\ndata: %s\n\n", eventType, string(jsonData))
	flusher.Flush()
}
