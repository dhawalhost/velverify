package llm

import (
	"context"
	"fmt"
	"time"

	"github.com/sashabaranov/go-openai"
)

type openRouterProvider struct {
	client  *openai.Client
	model   string
	timeout time.Duration
}

// NewOpenRouterProvider creates a new OpenRouter-backed LLM provider.
func NewOpenRouterProvider(apiKey, model string, timeout time.Duration) (Provider, error) {
	config := openai.DefaultConfig(apiKey)
	config.BaseURL = "https://openrouter.ai/api/v1"
	client := openai.NewClientWithConfig(config)

	return &openRouterProvider{
		client:  client,
		model:   model,
		timeout: timeout,
	}, nil
}

func (p *openRouterProvider) Chat(ctx context.Context, messages []Message, tools []Tool) (Message, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	openaiMessages := make([]openai.ChatCompletionMessage, len(messages))
	for i, m := range messages {
		openaiMessages[i] = openai.ChatCompletionMessage{
			Role:    m.Role,
			Content: m.Content,
		}
		if len(m.ToolCalls) > 0 {
			openaiMessages[i].ToolCalls = make([]openai.ToolCall, len(m.ToolCalls))
			for j, tc := range m.ToolCalls {
				openaiMessages[i].ToolCalls[j] = openai.ToolCall{
					ID:   tc.ID,
					Type: openai.ToolTypeFunction,
					Function: openai.FunctionCall{
						Name:      tc.Name,
						Arguments: tc.Arguments,
					},
				}
			}
		}
		if m.ToolCallID != "" {
			openaiMessages[i].ToolCallID = m.ToolCallID
		}
	}

	var openaiTools []openai.Tool
	if len(tools) > 0 {
		openaiTools = make([]openai.Tool, len(tools))
		for i, t := range tools {
			openaiTools[i] = openai.Tool{
				Type: openai.ToolTypeFunction,
				Function: &openai.FunctionDefinition{
					Name:        t.Name,
					Description: t.Description,
					Parameters:  t.Parameters,
				},
			}
		}
	}

	resp, err := p.client.CreateChatCompletion(
		ctx,
		openai.ChatCompletionRequest{
			Model:    p.model,
			Messages: openaiMessages,
			Tools:    openaiTools,
		},
	)

	if err != nil {
		return Message{}, fmt.Errorf("openrouter chat failed: %w", err)
	}

	if len(resp.Choices) == 0 {
		return Message{}, fmt.Errorf("openrouter returned no choices")
	}

	choice := resp.Choices[0].Message
	result := Message{
		Role:    choice.Role,
		Content: choice.Content,
	}

	if len(choice.ToolCalls) > 0 {
		result.ToolCalls = make([]ToolCall, len(choice.ToolCalls))
		for i, tc := range choice.ToolCalls {
			result.ToolCalls[i] = ToolCall{
				ID:        tc.ID,
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			}
		}
	}

	return result, nil
}

func (p *openRouterProvider) GenerateResponse(ctx context.Context, systemPrompt, userQuery string) (string, error) {
	messages := []Message{
		{Role: openai.ChatMessageRoleSystem, Content: systemPrompt},
		{Role: openai.ChatMessageRoleUser, Content: userQuery},
	}
	resp, err := p.Chat(ctx, messages, nil)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}
