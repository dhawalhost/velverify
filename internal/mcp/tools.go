package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/dhawalhost/wardseal/internal/governance"
	"github.com/dhawalhost/wardseal/internal/policy"
	"github.com/dhawalhost/wardseal/pkg/llm"
)

// ToolManager manages WardSeal tools for MCP.
type ToolManager struct {
	govSvc   governance.Service
	identity *Identity
}

func NewToolManager(govSvc governance.Service, identity *Identity) *ToolManager {
	return &ToolManager{
		govSvc:   govSvc,
		identity: identity,
	}
}

// RegisterTools registers the WardSeal tools with the MCP server.
func (tm *ToolManager) RegisterTools(s *Server) {
	s.RegisterHandler("tools/list", tm.handleListTools)
	s.RegisterHandler("tools/call", tm.handleCallTool)
}

func (tm *ToolManager) handleListTools(ctx context.Context, params json.RawMessage) (interface{}, error) {
	tools := []Tool{
		{
			Name:        "wardseal_get_stats",
			Description: "Retrieve high-level security and hygiene metrics for the organization.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
				},
				Required: []string{"tenant_id"},
			},
		},
		{
			Name:        "wardseal_list_requests",
			Description: "List pending access requests that require attention.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
					"status": {
						Type:        "string",
						Description: "Filter requests by status (pending, approved, rejected).",
						Enum:        []string{"pending", "approved", "rejected"},
					},
				},
				Required: []string{"tenant_id"},
			},
		},
		{
			Name:        "wardseal_list_identities",
			Description: "Search for users and groups in the directory.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
					"type": {
						Type:        "string",
						Description: "Type of identity to list (users or groups).",
						Enum:        []string{"users", "groups"},
					},
				},
				Required: []string{"tenant_id", "type"},
			},
		},
		{
			Name:        "wardseal_get_graph",
			Description: "Retrieve relationship tuples from the identity graph for a specific subject.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
					"subject_id": {
						Type:        "string",
						Description: "The ID of the subject (user or group) to traverse.",
					},
				},
				Required: []string{"tenant_id", "subject_id"},
			},
		},
		{
			Name:        "wardseal_propose_action",
			Description: "Propose a safety action (like revocation) for a suspicious account.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
					"target_id": {
						Type:        "string",
						Description: "The ID of the user to take action against.",
					},
					"action_type": {
						Type:        "string",
						Description: "The type of action to propose.",
						Enum:        []string{"revoke_all_access"},
					},
					"reason": {
						Type:        "string",
						Description: "The security justification for this action.",
					},
				},
				Required: []string{"tenant_id", "target_id", "action_type", "reason"},
			},
		},
		{
			Name:        "wardseal_evaluate_policy",
			Description: "Simulate a policy check for a human or machine actor performing an action.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
					"subject_id": {
						Type:        "string",
						Description: "The ID of the actor performing the action.",
					},
					"action": {
						Type:        "string",
						Description: "The action being performed (e.g., login, create_client, approve).",
					},
					"resource_type": {
						Type:        "string",
						Description: "The type of resource being accessed.",
					},
					"resource_id": {
						Type:        "string",
						Description: "The ID of the resource being accessed.",
					},
				},
				Required: []string{"tenant_id", "subject_id", "action", "resource_type", "resource_id"},
			},
		},
		{
			Name:        "wardseal_list_workloads",
			Description: "List machine identities (workloads) for a specific tenant.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
				},
				Required: []string{"tenant_id"},
			},
		},
		{
			Name:        "wardseal_list_devices",
			Description: "List registered devices and their trust status.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
				},
				Required: []string{"tenant_id"},
			},
		},
		{
			Name:        "wardseal_update_device_status",
			Description: "Update the trust status of a specific device.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
					"device_id": {
						Type:        "string",
						Description: "The ID of the device to update.",
					},
					"status": {
						Type:        "string",
						Description: "The new status (trusted, untrusted, pending).",
					},
				},
				Required: []string{"tenant_id", "device_id", "status"},
			},
		},
		{
			Name:        "wardseal_approve_request",
			Description: "Approve a pending access request.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
					"request_id": {
						Type:        "string",
						Description: "The ID of the access request to approve.",
					},
					"approver_id": {
						Type:        "string",
						Description: "The ID of the person/service approving the request.",
					},
					"comment": {
						Type:        "string",
						Description: "An optional comment for the approval.",
					},
				},
				Required: []string{"tenant_id", "request_id", "approver_id"},
			},
		},
		{
			Name:        "wardseal_list_organizations",
			Description: "List organizations under a specific tenant.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
				},
				Required: []string{"tenant_id"},
			},
		},
		{
			Name:        "wardseal_list_ip_policies",
			Description: "List IP-based access policies (blocking/allowing specific CIDRs).",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
				},
				Required: []string{"tenant_id"},
			},
		},
		{
			Name:        "wardseal_create_ip_policy",
			Description: "Create a new IP access policy.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
					"type": {
						Type:        "string",
						Description: "Policy type (allow or block).",
					},
					"cidr": {
						Type:        "string",
						Description: "The network range in CIDR notation (e.g., 10.0.0.0/24).",
					},
					"reason": {
						Type:        "string",
						Description: "The justification for the policy.",
					},
				},
				Required: []string{"tenant_id", "type", "cidr", "reason"},
			},
		},
		{
			Name:        "wardseal_list_clients",
			Description: "List OAuth2 clients (applications) registered with the platform.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]Property{
					"tenant_id": {
						Type:        "string",
						Description: "The unique identifier for the tenant.",
					},
				},
				Required: []string{"tenant_id"},
			},
		},
	}
	return map[string]interface{}{"tools": tools}, nil
}

func (tm *ToolManager) ListTools(ctx context.Context) ([]llm.Tool, error) {
	resp, err := tm.handleListTools(ctx, nil)
	if err != nil {
		return nil, err
	}
	m := resp.(map[string]interface{})
	mcpTools := m["tools"].([]Tool)

	llmTools := make([]llm.Tool, len(mcpTools))
	for i, t := range mcpTools {
		llmTools[i] = llm.Tool{
			Name:        t.Name,
			Description: t.Description,
			Parameters:  t.InputSchema,
		}
	}
	return llmTools, nil
}

func (tm *ToolManager) CallTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	req := CallToolRequest{
		Name:      name,
		Arguments: args,
	}
	params, _ := json.Marshal(req)
	return tm.handleCallTool(ctx, params)
}

func (tm *ToolManager) handleCallTool(ctx context.Context, params json.RawMessage) (interface{}, error) {
	var req CallToolRequest
	if err := json.Unmarshal(params, &req); err != nil {
		return nil, err
	}

	tenantID, _ := req.Arguments["tenant_id"].(string)
	if tenantID == "" {
		return ToolResponse{
			IsError: true,
			Content: []ToolContent{{Type: "text", Text: "Error: tenant_id is required"}},
		}, nil
	}

	// Authorization Check
	if tm.identity != nil {
		if tm.identity.TenantID != "*" && tm.identity.TenantID != tenantID {
			return ToolResponse{
				IsError: true,
				Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Unauthorized: Access to tenant %s is denied for this API Key", tenantID)}},
			}, nil
		}
	}

	switch req.Name {
	case "wardseal_get_stats":
		stats, err := tm.govSvc.GetDashboardStats(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		data, _ := json.MarshalIndent(stats, "", "  ")
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(data)}},
		}, nil

	case "wardseal_list_requests":
		status, _ := req.Arguments["status"].(string)
		requests, err := tm.govSvc.ListAccessRequests(ctx, tenantID, status)
		if err != nil {
			return nil, err
		}
		data, _ := json.MarshalIndent(requests, "", "  ")
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(data)}},
		}, nil

	case "wardseal_list_identities":
		identityType, _ := req.Arguments["type"].(string)
		if identityType == "users" {
			users, err := tm.govSvc.ListUsers(ctx, tenantID)
			if err != nil {
				return nil, err
			}
			data, _ := json.MarshalIndent(users, "", "  ")
			return ToolResponse{
				Content: []ToolContent{{Type: "text", Text: string(data)}},
			}, nil
		} else {
			groups, err := tm.govSvc.ListGroups(ctx, tenantID)
			if err != nil {
				return nil, err
			}
			data, _ := json.MarshalIndent(groups, "", "  ")
			return ToolResponse{
				Content: []ToolContent{{Type: "text", Text: string(data)}},
			}, nil
		}

	case "wardseal_get_graph":
		subjectID, _ := req.Arguments["subject_id"].(string)
		relationships, err := tm.govSvc.TraverseGraph(ctx, tenantID, subjectID)
		if err != nil {
			return nil, err
		}
		data, _ := json.MarshalIndent(relationships, "", "  ")
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(data)}},
		}, nil

	case "wardseal_propose_action":
		targetID, _ := req.Arguments["target_id"].(string)
		actionType, _ := req.Arguments["action_type"].(string)
		reason, _ := req.Arguments["reason"].(string)

		input := governance.ProposeSafetyActionInput{
			ActionType: actionType,
			TargetID:   targetID,
			Reason:     reason,
		}

		action, err := tm.govSvc.ProposeSafetyAction(ctx, tenantID, input)
		if err != nil {
			return nil, err
		}

		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Safety action %s proposed successfully for target %s. Reason: %s", action.ID, action.TargetID, action.Reason)}},
		}, nil

	case "wardseal_evaluate_policy":
		subjectID, _ := req.Arguments["subject_id"].(string)
		actionName, _ := req.Arguments["action"].(string)
		resType, _ := req.Arguments["resource_type"].(string)
		resID, _ := req.Arguments["resource_id"].(string)

		policyInput := policy.Input{
			Subject: policy.Subject{ID: subjectID},
			Action:  actionName,
			Resource: policy.Resource{
				Type: resType,
				ID:   resID,
			},
			Context: map[string]interface{}{
				"tenant_id": tenantID,
			},
		}

		allowed, reason, err := tm.govSvc.EvaluatePolicy(ctx, policyInput)
		if err != nil {
			return nil, err
		}

		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Allowed: %v\nReason: %s", allowed, reason)}},
		}, nil

	case "wardseal_list_workloads":
		workloads, err := tm.govSvc.ListWorkloads(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		data, _ := json.MarshalIndent(workloads, "", "  ")
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(data)}},
		}, nil

	case "wardseal_list_devices":
		devices, err := tm.govSvc.ListDevices(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		data, _ := json.MarshalIndent(devices, "", "  ")
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(data)}},
		}, nil

	case "wardseal_update_device_status":
		deviceID, _ := req.Arguments["device_id"].(string)
		status, _ := req.Arguments["status"].(string)
		if err := tm.govSvc.UpdateDeviceStatus(ctx, tenantID, deviceID, status); err != nil {
			return nil, err
		}
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Device %s status updated to %s", deviceID, status)}},
		}, nil

	case "wardseal_approve_request":
		requestID, _ := req.Arguments["request_id"].(string)
		approverID, _ := req.Arguments["approver_id"].(string)
		comment, _ := req.Arguments["comment"].(string)
		if err := tm.govSvc.ApproveAccessRequest(ctx, tenantID, requestID, approverID, comment); err != nil {
			return nil, err
		}
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("Access request %s approved", requestID)}},
		}, nil

	case "wardseal_list_organizations":
		orgs, err := tm.govSvc.ListOrganizations(ctx, tenantID, 100, 0)
		if err != nil {
			return nil, err
		}
		data, _ := json.MarshalIndent(orgs, "", "  ")
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(data)}},
		}, nil

	case "wardseal_list_ip_policies":
		policies, err := tm.govSvc.ListIPPolicies(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		data, _ := json.MarshalIndent(policies, "", "  ")
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(data)}},
		}, nil

	case "wardseal_create_ip_policy":
		policyType, _ := req.Arguments["type"].(string)
		cidr, _ := req.Arguments["cidr"].(string)
		reason, _ := req.Arguments["reason"].(string)
		req := governance.CreateIPPolicyRequest{
			Type:   policyType,
			CIDR:   cidr,
			Reason: reason,
		}
		p, err := tm.govSvc.CreateIPPolicy(ctx, tenantID, req)
		if err != nil {
			return nil, err
		}
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: fmt.Sprintf("IP policy %s created: %s %s", p.ID, p.Type, p.CIDR)}},
		}, nil

	case "wardseal_list_clients":
		clients, err := tm.govSvc.ListOAuthClients(ctx, tenantID)
		if err != nil {
			return nil, err
		}
		data, _ := json.MarshalIndent(clients, "", "  ")
		return ToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(data)}},
		}, nil

	default:
		return nil, fmt.Errorf("unknown tool: %s", req.Name)
	}
}
