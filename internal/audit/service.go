package audit

import (
	"context"
	"encoding/json"
	"fmt"
)

// Service defines audit service operations.
type Service interface {
	// Log creates an audit log entry.
	Log(ctx context.Context, input LogInput) error

	// Query retrieves audit logs with filtering.
	Query(ctx context.Context, params QueryParams) ([]Event, int, error)

	// Export retrieves all matching audit logs for export.
	Export(ctx context.Context, params QueryParams) ([]Event, error)

	// GetEvent retrieves a single audit event.
	GetEvent(ctx context.Context, tenantID, id string) (Event, error)

	// GetStats retrieves statistics for the audit logs.
	GetStats(ctx context.Context, tenantID string, lookbackDays int) (Stats, error)
}

type service struct {
	store Repository
}

// NewService creates a new audit service.
func NewService(store Repository) Service {
	return &service{store: store}
}

func (s *service) Log(ctx context.Context, input LogInput) error {
	if input.TenantID == "" {
		return fmt.Errorf("tenant_id is required")
	}
	if input.Action == "" {
		return fmt.Errorf("action is required")
	}
	if input.ResourceType == "" {
		return fmt.Errorf("resource_type is required")
	}
	if input.ActorType == "" {
		input.ActorType = "user"
	}
	if input.Outcome == "" {
		input.Outcome = "success"
	}

	// Serialize details to JSON
	var details *json.RawMessage
	if input.Details != nil {
		b, err := json.Marshal(input.Details)
		if err != nil {
			return fmt.Errorf("failed to serialize details: %w", err)
		}
		raw := json.RawMessage(b)
		details = &raw
	}

	e := Event{
		TenantID:     input.TenantID,
		ActorID:      input.ActorID,
		ActorType:    input.ActorType,
		Action:       input.Action,
		ResourceType: input.ResourceType,
		ResourceID:   input.ResourceID,
		ResourceName: input.ResourceName,
		Details:      details,
		IPAddress:    input.IPAddress,
		UserAgent:    input.UserAgent,
		Outcome:      input.Outcome,
	}

	_, err := s.store.Log(ctx, e)
	return err
}

func (s *service) Query(ctx context.Context, params QueryParams) ([]Event, int, error) {
	if params.Limit == 0 {
		params.Limit = 100
	}
	if params.Limit > 1000 {
		params.Limit = 1000
	}
	return s.store.Query(ctx, params)
}

func (s *service) Export(ctx context.Context, params QueryParams) ([]Event, error) {
	if params.Limit == 0 {
		params.Limit = 10000
	}
	if params.Limit > 50000 {
		params.Limit = 50000
	}
	events, _, err := s.store.Query(ctx, params)
	return events, err
}

func (s *service) GetEvent(ctx context.Context, tenantID, id string) (Event, error) {
	return s.store.GetEvent(ctx, tenantID, id)
}

func (s *service) GetStats(ctx context.Context, tenantID string, lookbackDays int) (Stats, error) {
	if lookbackDays <= 0 {
		lookbackDays = 7 // Default to 7 days
	}
	if lookbackDays > 90 {
		lookbackDays = 90 // Max 90 days for performance
	}
	return s.store.GetStats(ctx, tenantID, lookbackDays)
}
