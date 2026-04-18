package audit

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dhawalhost/wardseal/pkg/eventbus"
	"go.uber.org/zap"
)

// AuditSubscriber listens to EventBus topics and records them in the audit logs.
type AuditSubscriber struct {
	auditSvc Service
	bus      eventbus.EventBus
	log      *zap.Logger
}

// NewAuditSubscriber creates a new AuditSubscriber.
func NewAuditSubscriber(auditSvc Service, bus eventbus.EventBus, log *zap.Logger) *AuditSubscriber {
	return &AuditSubscriber{
		auditSvc: auditSvc,
		bus:      bus,
		log:      log,
	}
}

// RegisterSubscribers registers for all high-value system topics.
func (s *AuditSubscriber) RegisterSubscribers(ctx context.Context) error {
	topics := []string{
		"UserCreated",
		"UserDeactivated",
		"GroupMembershipChanged",
		"AccessRequestCreated",
		"AccessRequestApproved",
		"AccessRequestRejected",
		"EndpointRegistered",
		"EndpointTrustUpdated",
		"dlq:failed_events",
	}

	for _, topic := range topics {
		t := topic // closure
		err := s.bus.Subscribe(ctx, t, func(ctx context.Context, payload []byte) error {
			return s.handleEvent(ctx, t, payload)
		})
		if err != nil {
			return fmt.Errorf("failed to subscribe to %s: %w", t, err)
		}
	}

	return nil
}

func (s *AuditSubscriber) handleEvent(ctx context.Context, topic string, payload []byte) error {
	var data map[string]interface{}
	if err := json.Unmarshal(payload, &data); err != nil {
		return fmt.Errorf("audit subscriber unmarshal failed: %w", err)
	}

	tenantID, _ := data["tenant_id"].(string)
	if tenantID == "" {
		tenantID = "system" // Fallback
	}

	// Map topic to audit action
	action := topic
	resourceType := "system"
	resourceID := ""

	switch topic {
	case "UserCreated":
		resourceType = "user"
		if id, ok := data["user_id"].(string); ok {
			resourceID = id
		}
	case "UserDeactivated":
		resourceType = "user"
		if id, ok := data["user_id"].(string); ok {
			resourceID = id
		}
	case "GroupMembershipChanged":
		resourceType = "group"
		if id, ok := data["group_id"].(string); ok {
			resourceID = id
		}
	case "AccessRequestCreated", "AccessRequestApproved", "AccessRequestRejected":
		resourceType = "governance"
		if id, ok := data["request_id"].(string); ok {
			resourceID = id
		}
	case "EndpointRegistered", "EndpointTrustUpdated":
		resourceType = "endpoint"
		if id, ok := data["device_id"].(string); ok {
			resourceID = id
		}
	case "dlq:failed_events":
		action = "message_failure"
		resourceType = "eventbus"
	}

	input := LogInput{
		TenantID:     tenantID,
		Action:       action,
		ResourceType: resourceType,
		Outcome:      "success",
		Details:      data,
	}
	
	if resourceID != "" {
		input.ResourceID = &resourceID
	}

	return s.auditSvc.Log(ctx, input)
}
