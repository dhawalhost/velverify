package auth

import (
	"context"
	"testing"

	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/google/uuid"
)

func TestRiskEngine_IPPolicy(t *testing.T) {
	ctx := context.Background()
	tenantID := uuid.New().String()
	
	// Mock IP Policy Store
	repo := &mockIPPolicyRepo{
		policies: []IPPolicy{
			{
				Type:     IPPolicyBlock,
				CIDR:     strPtr("192.168.1.0/24"),
				TenantID: tenantID,
			},
			{
				Type:     IPPolicyBlock,
				Country:  strPtr("CN"),
				TenantID: tenantID,
			},
		},
	}

	engine := NewRiskEngine(nil, nil, nil).WithIPPolicy(repo, nil)

	ctx = middleware.InjectTenantID(ctx, tenantID)

	// Test blocked IP
	res, err := engine.Evaluate(ctx, "user-123", "", "192.168.1.5")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if res.Score != 100 {
		t.Errorf("expected score 100 for blocked IP, got %d", res.Score)
	}
	found := false
	for _, f := range res.Factors {
		if f == "ip_block_list" || len(f) > 10 && f[:10] == "ip_blocked" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected ip_blocked factor in %v", res.Factors)
	}

	// Test allowed IP
	res, err = engine.Evaluate(ctx, "user-123", "", "1.1.1.1")
	if err != nil {
		t.Fatalf("Evaluate failed: %v", err)
	}
	if res.Score >= 100 {
		t.Errorf("expected score < 100 for allowed IP, got %d", res.Score)
	}
}


