package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Service defines the interface for the policy service.
type Service interface {
	HealthCheck(ctx context.Context) (bool, error)
	Evaluate(ctx context.Context, input Input) (bool, string, error)
	
	// Policy Management
	ListPolicies(ctx context.Context, tenantID string) ([]Policy, error)
	GetPolicy(ctx context.Context, tenantID, id string) (Policy, error)
	CreatePolicy(ctx context.Context, p Policy) (string, error)
	UpdatePolicy(ctx context.Context, p Policy) error
	DeletePolicy(ctx context.Context, tenantID, id string) error
}

type policyService struct {
	repo   Repository
	engine Engine
}

// NewService creates a new policy service.
func NewService(repo Repository, engine Engine) Service {
	return &policyService{
		repo:   repo,
		engine: engine,
	}
}

func (s *policyService) HealthCheck(ctx context.Context) (bool, error) {
	return true, nil
}

func (s *policyService) Evaluate(ctx context.Context, input Input) (bool, string, error) {
	// The engine will now take the repository to load dynamic rules
	return s.engine.Evaluate(ctx, input)
}

func (s *policyService) ListPolicies(ctx context.Context, tenantID string) ([]Policy, error) {
	return s.repo.List(ctx, tenantID)
}

func (s *policyService) CreatePolicy(ctx context.Context, p Policy) (string, error) {
	if err := s.validateRule(p.RuleType, p.RuleData); err != nil {
		return "", err
	}
	return s.repo.Create(ctx, p)
}

func (s *policyService) GetPolicy(ctx context.Context, tenantID, id string) (Policy, error) {
	return s.repo.Get(ctx, tenantID, id)
}

func (s *policyService) UpdatePolicy(ctx context.Context, p Policy) error {
	if err := s.validateRule(p.RuleType, p.RuleData); err != nil {
		return err
	}
	return s.repo.Update(ctx, p)
}

func (s *policyService) DeletePolicy(ctx context.Context, tenantID, id string) error {
	return s.repo.Delete(ctx, tenantID, id)
}

func (s *policyService) validateRule(ruleType RuleType, data []byte) error {
	if len(data) == 0 {
		return fmt.Errorf("rule data is required")
	}

	switch ruleType {
	case RuleTypeSimple:
		var rule SimpleRule
		if err := json.Unmarshal(data, &rule); err != nil {
			return fmt.Errorf("invalid simple rule data: %w", err)
		}
		if len(rule.Conditions) == 0 {
			return fmt.Errorf("simple rule must have at least one condition")
		}
	case RuleTypeCEL:
		// Basic check: should be a non-empty string in RuleData (usually wrapped in JSON)
		if strings.TrimSpace(string(data)) == "" {
			return fmt.Errorf("CEL expression is required")
		}
	case RuleTypeSODCheck, RuleTypeDeviceTrust, RuleTypeMFARequired, RuleTypeGeoFencing:
		// These typically have specific or empty config, skip or add minor checks
	default:
		return fmt.Errorf("unsupported rule type: %s", ruleType)
	}

	return nil
}
