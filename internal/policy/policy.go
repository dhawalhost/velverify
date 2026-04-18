package policy

import (
	"context"
	"time"
)

type RuleType string

const (
	RuleTypeMFARequired RuleType = "mfa_required"
	RuleTypeGeoFencing  RuleType = "geo_fencing"
	RuleTypeDeviceTrust RuleType = "device_trust"
	RuleTypeSODCheck    RuleType = "sod_check"
	RuleTypeCEL         RuleType = "cel"
	RuleTypeSimple      RuleType = "simple"
)

// Policy represents a tenant-specific access rule.
type Policy struct {
	ID        string    `json:"id" db:"id"`
	TenantID  string    `json:"tenant_id" db:"tenant_id"`
	Name      string    `json:"name" db:"name"`
	RuleType  RuleType  `json:"rule_type" db:"rule_type"`
	RuleData  []byte    `json:"rule_data" db:"rule_data"` // JSONB
	IsEnabled bool      `json:"is_enabled" db:"is_enabled"`
	CreatedAt time.Time `json:"created_at" db:"created_at"`
	UpdatedAt time.Time `json:"updated_at" db:"updated_at"`
}

// Input represents the data provided for policy evaluation.
type Input struct {
	Subject  Subject                `json:"subject"`
	Action   string                 `json:"action"`
	Resource Resource               `json:"resource"`
	Context  map[string]interface{} `json:"context,omitempty"`
}

type Subject struct {
	ID    string   `json:"id"`
	Roles []string `json:"roles"`
}

type Resource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
	// Additional resource attributes can be passed in Context
}

// Engine defines the interface for policy evaluation.
type Engine interface {
	// Evaluate determines if an action is allowed based on the input.
	// It returns allowed (bool), decision reason (string), and any error.
	Evaluate(ctx context.Context, input Input) (bool, string, error)
}

// Repository defines policy storage operations.
type Repository interface {
	List(ctx context.Context, tenantID string) ([]Policy, error)
	Get(ctx context.Context, tenantID, id string) (Policy, error)
	Create(ctx context.Context, p Policy) (string, error)
	Update(ctx context.Context, p Policy) error
	Delete(ctx context.Context, tenantID, id string) error
	GetByType(ctx context.Context, tenantID string, ruleType RuleType) ([]Policy, error)
}
