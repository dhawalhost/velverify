package chatops

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dhawalhost/wardseal/internal/governance"
	"github.com/dhawalhost/wardseal/pkg/eventbus"
	"go.uber.org/zap"
)

// ChatOpsSubscriber listens for events that require human intervention.
type ChatOpsSubscriber struct {
	slack *SlackHandler
	bus   eventbus.EventBus
	log   *zap.Logger
}

// NewChatOpsSubscriber creates a new ChatOpsSubscriber.
func NewChatOpsSubscriber(slack *SlackHandler, bus eventbus.EventBus, log *zap.Logger) *ChatOpsSubscriber {
	return &ChatOpsSubscriber{
		slack: slack,
		bus:   bus,
		log:   log,
	}
}

// RegisterSubscribers registers for interactive topics.
func (s *ChatOpsSubscriber) RegisterSubscribers(ctx context.Context) error {
	err := s.bus.Subscribe(ctx, "ProposedRevocation", func(ctx context.Context, payload []byte) error {
		return s.handleProposedRevocation(ctx, payload)
	})
	if err != nil {
		return fmt.Errorf("failed to subscribe to ProposedRevocation: %w", err)
	}
	return nil
}

func (s *ChatOpsSubscriber) handleProposedRevocation(ctx context.Context, payload []byte) error {
	var action governance.SafetyAction
	if err := json.Unmarshal(payload, &action); err != nil {
		return err
	}

	s.log.Info("safety check: notifying slack about internal proposal", 
		zap.String("action_id", action.ID),
		zap.String("target_id", action.TargetID),
	)

	// Trigger the Slack interactive message
	return s.slack.NotifyProposedRevocation(ctx, action)
}
