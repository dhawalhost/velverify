package policy

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// SimpleEvaluator provides a basic attribute-based matching engine for JSON/YAML policies.
type SimpleEvaluator struct{}

type SimpleRule struct {
	LogicalOp  string      `json:"logical_op"` // "AND" or "OR"
	Conditions []Condition `json:"conditions"`
}

type Condition struct {
	Attribute string      `json:"attribute"`
	Operator  string      `json:"operator"` // "equals", "not_equals", "contains", "matches"
	Value     interface{} `json:"value"`
}

func (e *SimpleEvaluator) Name() string {
	return "simple"
}

func (e *SimpleEvaluator) Evaluate(ctx context.Context, input Input, p *Policy) (bool, string, error) {
	var rule SimpleRule
	if err := json.Unmarshal(p.RuleData, &rule); err != nil {
		return false, "Invalid simple rule data", fmt.Errorf("failed to parse simple rule: %w", err)
	}

	if len(rule.Conditions) == 0 {
		return true, "Allowed (No conditions defined)", nil
	}

	logicalOp := strings.ToUpper(rule.LogicalOp)
	if logicalOp == "" {
		logicalOp = "AND"
	}

	results := make([]bool, len(rule.Conditions))
	for i, cond := range rule.Conditions {
		matched, err := e.matchCondition(input, cond)
		if err != nil {
			return false, "Policy Evaluation Error", err
		}
		results[i] = matched
	}

	// Apply logical operation
	if logicalOp == "OR" {
		for _, r := range results {
			if r {
				return true, "Allowed", nil
			}
		}
		return false, fmt.Sprintf("Tenant Policy Violation: %s - None of the OR conditions were met", p.Name), nil
	}

	// Default to AND
	for _, r := range results {
		if !r {
			return false, fmt.Sprintf("Tenant Policy Violation: %s - Required security conditions not met", p.Name), nil
		}
	}

	return true, "Allowed", nil
}

func (e *SimpleEvaluator) matchCondition(input Input, cond Condition) (bool, error) {
	val := e.resolveAttribute(input, cond.Attribute)
	if val == nil {
		return false, nil
	}

	switch cond.Operator {
	case "equals":
		return fmt.Sprintf("%v", val) == fmt.Sprintf("%v", cond.Value), nil
	case "not_equals":
		return fmt.Sprintf("%v", val) != fmt.Sprintf("%v", cond.Value), nil
	case "contains":
		return e.contains(val, cond.Value), nil
	case "matches":
		pattern, ok := cond.Value.(string)
		if !ok {
			return false, fmt.Errorf("invalid regex pattern type")
		}
		matched, _ := regexp.MatchString(pattern, fmt.Sprintf("%v", val))
		return matched, nil
	default:
		return false, fmt.Errorf("unsupported operator: %s", cond.Operator)
	}
}

func (e *SimpleEvaluator) resolveAttribute(input Input, attr string) interface{} {
	parts := strings.Split(attr, ".")
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "subject":
		if len(parts) < 2 {
			return nil
		}
		switch parts[1] {
		case "id":
			return input.Subject.ID
		case "roles":
			return input.Subject.Roles
		}
	case "resource":
		if len(parts) < 2 {
			return nil
		}
		switch parts[1] {
		case "type":
			return input.Resource.Type
		case "id":
			return input.Resource.ID
		}
	case "action":
		return input.Action
	case "context":
		if len(parts) < 2 {
			return nil
		}
		return input.Context[parts[1]]
	}

	return nil
}

func (e *SimpleEvaluator) contains(source interface{}, target interface{}) bool {
	targetStr := fmt.Sprintf("%v", target)

	switch v := source.(type) {
	case string:
		return strings.Contains(v, targetStr)
	case []string:
		for _, s := range v {
			if s == targetStr {
				return true
			}
		}
	case []interface{}:
		for _, item := range v {
			if fmt.Sprintf("%v", item) == targetStr {
				return true
			}
		}
	}
	return false
}
