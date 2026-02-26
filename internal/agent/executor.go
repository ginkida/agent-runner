package agent

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"time"
)

const (
	MaxFunctionCallsPerResponse = 10
	MaxConcurrentToolExecutions = 5
)

// Executor handles parallel execution of tool calls.
type Executor struct {
	registry *Registry
	timeout  time.Duration
}

// NewExecutor creates a tool executor with the given registry.
func NewExecutor(registry *Registry) *Executor {
	return &Executor{
		registry: registry,
		timeout:  2 * time.Minute,
	}
}

// Execute runs a batch of function calls and returns their responses.
func (e *Executor) Execute(ctx context.Context, calls []*FunctionCall) ([]*FunctionResponse, error) {
	if len(calls) > MaxFunctionCallsPerResponse {
		calls = calls[:MaxFunctionCallsPerResponse]
	}

	results := make([]*FunctionResponse, len(calls))

	if len(calls) == 1 {
		result := func() (r *ToolResult) {
			defer func() {
				if rv := recover(); rv != nil {
					r = NewErrorResult(fmt.Sprintf("panic: %v", rv))
				}
			}()
			return e.executeTool(ctx, calls[0])
		}()
		results[0] = &FunctionResponse{
			ID:       calls[0].ID,
			Name:     calls[0].Name,
			Response: result.ToMap(),
		}
		return results, nil
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	sem := make(chan struct{}, MaxConcurrentToolExecutions)

	for i, call := range calls {
		wg.Add(1)
		go func(idx int, fc *FunctionCall) {
			defer wg.Done()

			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				mu.Lock()
				results[idx] = &FunctionResponse{
					ID:       fc.ID,
					Name:     fc.Name,
					Response: NewErrorResult("cancelled").ToMap(),
				}
				mu.Unlock()
				return
			}

			defer func() {
				if r := recover(); r != nil {
					buf := make([]byte, 4096)
					runtime.Stack(buf, false)
					mu.Lock()
					results[idx] = &FunctionResponse{
						ID:       fc.ID,
						Name:     fc.Name,
						Response: NewErrorResult(fmt.Sprintf("panic: %v", r)).ToMap(),
					}
					mu.Unlock()
				}
			}()

			result := e.executeTool(ctx, fc)
			mu.Lock()
			results[idx] = &FunctionResponse{
				ID:       fc.ID,
				Name:     fc.Name,
				Response: result.ToMap(),
			}
			mu.Unlock()
		}(i, call)
	}

	wg.Wait()
	return results, nil
}

func (e *Executor) executeTool(ctx context.Context, call *FunctionCall) *ToolResult {
	tool, ok := e.registry.Get(call.Name)
	if !ok {
		return NewErrorResult(fmt.Sprintf("unknown tool: %s", call.Name))
	}

	execCtx, cancel := context.WithTimeout(ctx, e.timeout)
	defer cancel()

	result, err := tool.Execute(execCtx, call.Args)
	if err != nil {
		return NewErrorResult(err.Error())
	}
	return result
}
