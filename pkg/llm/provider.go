package llm

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Message represents a single message in a chat conversation.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// Tool represents a function the LLM can decide to call.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	Parameters  interface{} `json:"parameters"` // JSON Schema
}

// ToolCall represents a specific invocation of a tool by the LLM.
type ToolCall struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON string
}

// Provider defines the interface for LLM interactions.
type Provider interface {
	GenerateResponse(ctx context.Context, systemPrompt, userQuery string) (string, error)
	Chat(ctx context.Context, messages []Message, tools []Tool) (Message, error)
}

// NewProvider is a factory function that returns an LLM provider based on environment variables.
func NewProvider() (Provider, error) {
	providerType := os.Getenv("LLM_PROVIDER")
	if providerType == "" {
		providerType = "openrouter" // Default
	}

	timeoutStr := os.Getenv("LLM_TIMEOUT")
	timeout := 15 * time.Second // Default
	if timeoutStr != "" {
		if t, err := strconv.Atoi(timeoutStr); err == nil {
			timeout = time.Duration(t) * time.Second
		}
	}

	switch providerType {
	case "gemini":
		apiKey := os.Getenv("GEMINI_API_KEY")
		if apiKey == "" {
			return nil, fmt.Errorf("GEMINI_API_KEY environment variable is not set")
		}
		return NewGeminiProvider(apiKey, timeout)
	case "openrouter":
		apiKey := os.Getenv("OPENROUTER_API_KEY")
		if apiKey == "" {
			return nil, fmt.Errorf("OPENROUTER_API_KEY environment variable is not set")
		}
		model := os.Getenv("OPENROUTER_MODEL")
		if model == "" {
			model = "openai/gpt-oss-120b:free" // Default model
		}
		return NewOpenRouterProvider(apiKey, model, timeout)
	default:
		return nil, fmt.Errorf("unsupported LLM provider: %s", providerType)
	}
}
