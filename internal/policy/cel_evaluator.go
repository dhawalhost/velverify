package policy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"
)

// CELEvaluator implements dynamic policy evaluation using Google's Common Expression Language.
type CELEvaluator struct {
	env *cel.Env
}

// NewCELEvaluator creates a new CELEvaluator with a pre-configured CEL environment.
func NewCELEvaluator() *CELEvaluator {
	env, err := cel.NewEnv(
		cel.Variable("subject", cel.MapType(cel.StringType, cel.AnyType)),
		cel.Variable("resource", cel.MapType(cel.StringType, cel.AnyType)),
		cel.Variable("action", cel.StringType),
		cel.Variable("context", cel.MapType(cel.StringType, cel.AnyType)),
	)
	if err != nil {
		// This should only happen if the type definitions above are invalid (programming error)
		return nil
	}
	return &CELEvaluator{env: env}
}

func (e *CELEvaluator) Name() string { return "CEL" }

func (e *CELEvaluator) Evaluate(ctx context.Context, input Input, p *Policy) (bool, string, error) {
	if e == nil || e.env == nil {
		return false, "", fmt.Errorf("CEL environment not initialized")
	}

	var rule string
	if err := json.Unmarshal(p.RuleData, &rule); err != nil {
		// If it's not a quoted string, try unmarshaling as a struct with an "expression" field
		var ruleObj struct {
			Expression string `json:"expression"`
		}
		if err := json.Unmarshal(p.RuleData, &ruleObj); err == nil && ruleObj.Expression != "" {
			rule = ruleObj.Expression
		} else {
			return false, "", fmt.Errorf("invalid rule data for CEL: expected string or {expression: string}")
		}
	}

	// 1. Compile the expression
	ast, iss := e.env.Compile(rule)
	if iss.Err() != nil {
		return false, "", fmt.Errorf("failed to compile CEL expression: %v", iss.Err())
	}

	// 2. Create the program
	program, err := e.env.Program(ast)
	if err != nil {
		return false, "", fmt.Errorf("failed to create CEL program: %w", err)
	}

	// 3. Prepare the activation data
	// Note: In a production system, we'd map our Input structs to protobufs or clean maps.
	activation := map[string]interface{}{
		"subject": map[string]interface{}{
			"id":    input.Subject.ID,
			"roles": input.Subject.Roles,
		},
		"resource": map[string]interface{}{
			"type": input.Resource.Type,
			"id":   input.Resource.ID,
		},
		"action":  input.Action,
		"context": input.Context,
	}

	// 4. Evaluate
	out, _, err := program.ContextEval(ctx, activation)
	if err != nil {
		return false, "", fmt.Errorf("failed to evaluate CEL expression: %w", err)
	}

	// 5. Interpret result
	if out.Value().(bool) {
		return true, "Allowed by CEL policy", nil
	}

	return false, "Denied by CEL policy", nil
}
