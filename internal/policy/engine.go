package policy

import (
	"context"
)

// RuleEvaluator defines the interface for specific policy logic modules.
type RuleEvaluator interface {
	Name() string
	Evaluate(ctx context.Context, input Input, p *Policy) (bool, string, error)
}

// simpleEngine coordinates the evaluation of various policy rules.
type simpleEngine struct {
	repo       Repository
	evaluators map[RuleType]RuleEvaluator
}

// NewSimpleEngine creates a new policy engine and registers core evaluators.
func NewSimpleEngine(repo Repository) Engine {
	e := &simpleEngine{
		repo:       repo,
		evaluators: make(map[RuleType]RuleEvaluator),
	}

	// Register core evaluators
	e.Register(RuleTypeDeviceTrust, &DeviceTrustEvaluator{})
	e.Register(RuleTypeCEL, NewCELEvaluator())
	e.Register(RuleTypeSimple, &SimpleEvaluator{})

	return e
}

func (e *simpleEngine) Register(ruleType RuleType, eval RuleEvaluator) {
	e.evaluators[ruleType] = eval
}

func (e *simpleEngine) Evaluate(ctx context.Context, input Input) (bool, string, error) {
	// 1. CORE SYSTEM RULES (Hardcoded for maximum safety)

	// Separation of Duties (SOD) check
	// This remains hardcoded as a "Guardrail" rule that cannot be overridden by tenant policy
	if requesterID, ok := input.Context["requester_id"].(string); ok {
		if input.Subject.ID == requesterID && input.Action == "approve" {
			return false, "Policy Violation: Separation of Duties - Cannot approve own request", nil
		}
	}

	// 2. DYNAMIC TENANT POLICIES (Loaded from DB)
	tenantID, _ := input.Context["tenant_id"].(string)
	if tenantID == "" {
		tenantID = "default"
	}

	if e.repo != nil {
		policies, err := e.repo.List(ctx, tenantID)
		if err == nil {
			for _, p := range policies {
				if !p.IsEnabled {
					continue
				}

				// Check if we have a registered evaluator for this rule type
				if evaluator, ok := e.evaluators[p.RuleType]; ok {
					allowed, reason, err := evaluator.Evaluate(ctx, input, &p)
					if err != nil {
						return false, "Internal Error during policy evaluation", err
					}
					if !allowed {
						return false, reason, nil
					}
				}
			}
		}
	}

	return true, "Allowed", nil
}
