package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/generative-ai-go/genai"
	"google.golang.org/api/option"
)

type geminiProvider struct {
	client  *genai.Client
	timeout time.Duration
}

// NewGeminiProvider creates a new Gemini-backed LLM provider.
func NewGeminiProvider(apiKey string, timeout time.Duration) (Provider, error) {
	ctx := context.Background()
	client, err := genai.NewClient(ctx, option.WithAPIKey(apiKey))
	if err != nil {
		return nil, fmt.Errorf("failed to create gemini client: %w", err)
	}

	return &geminiProvider{
		client:  client,
		timeout: timeout,
	}, nil
}

func (p *geminiProvider) Chat(ctx context.Context, messages []Message, tools []Tool) (Message, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()

	model := p.client.GenerativeModel("gemini-1.5-flash")

	// Set system instruction if provided in the first message
	if len(messages) > 0 && messages[0].Role == "system" {
		model.SystemInstruction = &genai.Content{
			Parts: []genai.Part{genai.Text(messages[0].Content)},
		}
		messages = messages[1:]
	}

	if len(tools) > 0 {
		var decls []*genai.FunctionDeclaration
		for _, t := range tools {
			// Basic schema mapping - in a real app we'd convert JSON Schema to genai.Schema
			decls = append(decls, &genai.FunctionDeclaration{
				Name:        t.Name,
				Description: t.Description,
			})
		}
		model.Tools = []*genai.Tool{
			{FunctionDeclarations: decls},
		}
	}

	session := model.StartChat()
	// Map history (excluding the last message which we'll send via SendMessage)
	if len(messages) > 1 {
		for _, m := range messages[:len(messages)-1] {
			role := "user"
			if m.Role == "assistant" || m.Role == "model" {
				role = "model"
			}
			session.History = append(session.History, &genai.Content{
				Role:  role,
				Parts: []genai.Part{genai.Text(m.Content)},
			})
		}
	}

	lastMsg := messages[len(messages)-1]
	resp, err := session.SendMessage(ctx, genai.Text(lastMsg.Content))
	if err != nil {
		return Message{}, fmt.Errorf("gemini chat failed: %w", err)
	}

	if len(resp.Candidates) == 0 || len(resp.Candidates[0].Content.Parts) == 0 {
		return Message{}, fmt.Errorf("gemini returned no candidates")
	}

	cand := resp.Candidates[0].Content
	result := Message{
		Role: "assistant",
	}

	for _, part := range cand.Parts {
		if text, ok := part.(genai.Text); ok {
			result.Content += string(text)
		} else if fn, ok := part.(genai.FunctionCall); ok {
			args, _ := json.Marshal(fn.Args)
			result.ToolCalls = append(result.ToolCalls, ToolCall{
				ID:        "call_" + fn.Name, // Gemini doesn't always provide a call ID in the same way
				Name:      fn.Name,
				Arguments: string(args),
			})
		}
	}

	return result, nil
}

func (p *geminiProvider) GenerateResponse(ctx context.Context, systemPrompt, userQuery string) (string, error) {
	messages := []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: userQuery},
	}
	resp, err := p.Chat(ctx, messages, nil)
	if err != nil {
		return "", err
	}
	return resp.Content, nil
}
