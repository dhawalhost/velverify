package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/dhawalhost/wardseal/internal/auth"
	"github.com/dhawalhost/wardseal/internal/governance"
	"github.com/dhawalhost/wardseal/internal/oauthclient"
)

type mockGovSvc struct {
	governance.Service
	getDashboardStatsFn func(ctx context.Context, tenantID string) (governance.DashboardStats, error)
	listWorkloadsFn     func(ctx context.Context, tenantID string) ([]auth.Workload, error)
	listDevicesFn       func(ctx context.Context, tenantID string) ([]governance.Device, error)
	listClientsFn       func(ctx context.Context, tenantID string) ([]oauthclient.Client, error)
}

func (m *mockGovSvc) GetDashboardStats(ctx context.Context, tenantID string) (governance.DashboardStats, error) {
	return m.getDashboardStatsFn(ctx, tenantID)
}

func (m *mockGovSvc) ListWorkloads(ctx context.Context, tenantID string) ([]auth.Workload, error) {
	if m.listWorkloadsFn != nil {
		return m.listWorkloadsFn(ctx, tenantID)
	}
	return nil, nil
}

func (m *mockGovSvc) ListDevices(ctx context.Context, tenantID string) ([]governance.Device, error) {
	if m.listDevicesFn != nil {
		return m.listDevicesFn(ctx, tenantID)
	}
	return nil, nil
}

func (m *mockGovSvc) ListOAuthClients(ctx context.Context, tenantID string) ([]oauthclient.Client, error) {
	if m.listClientsFn != nil {
		return m.listClientsFn(ctx, tenantID)
	}
	return nil, nil
}

func TestToolManager_ListTools(t *testing.T) {
	tm := NewToolManager(&mockGovSvc{}, nil)
	res, err := tm.handleListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}

	tools := res.(map[string]interface{})["tools"].([]Tool)
	
	requiredTools := []string{
		"wardseal_get_stats",
		"wardseal_list_workloads",
		"wardseal_list_devices",
		"wardseal_list_clients",
		"wardseal_approve_request",
	}

	for _, req := range requiredTools {
		found := false
		for _, tool := range tools {
			if tool.Name == req {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected tool %s not found", req)
		}
	}
}

func TestToolManager_CallListWorkloads(t *testing.T) {
	mock := &mockGovSvc{
		listWorkloadsFn: func(ctx context.Context, tenantID string) ([]auth.Workload, error) {
			return []auth.Workload{{ID: "w1", Name: "test-workload"}}, nil
		},
	}
	tm := NewToolManager(mock, nil)

	params := map[string]interface{}{
		"name": "wardseal_list_workloads",
		"arguments": map[string]interface{}{
			"tenant_id": "test-tenant",
		},
	}
	rawParams, _ := json.Marshal(params)

	res, err := tm.handleCallTool(context.Background(), rawParams)
	if err != nil {
		t.Fatal(err)
	}

	resp := res.(ToolResponse)
	if resp.IsError {
		t.Fatalf("tool call failed: %v", resp.Content[0].Text)
	}

	if resp.Content[0].Text == "" {
		t.Error("expected non-empty response text")
	}
}
