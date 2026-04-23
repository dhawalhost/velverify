package policy

import (
	"context"
	"fmt"
)

// DeviceTrustEvaluator enforces that actions can only be performed from trusted devices.
type DeviceTrustEvaluator struct{}

func (e *DeviceTrustEvaluator) Name() string {
	return "device_trust"
}

func (e *DeviceTrustEvaluator) Evaluate(ctx context.Context, input Input, p *Policy) (bool, string, error) {
	trustStatus, ok := input.Context["device_trust"].(string)

	// If the context is missing or status is not 'trusted', fail the policy
	if !ok || trustStatus != "trusted" {
		displayReason := fmt.Sprintf("Tenant Policy Violation: %s - A trusted device is required for this action", p.Name)
		if trustStatus != "" {
			displayReason += fmt.Sprintf(" (Current status: %s)", trustStatus)
		}
		return false, displayReason, nil
	}

	return true, "Allowed", nil
}

// Future: CELEvaluator would go here...
// type CELEvaluator struct { ... }
