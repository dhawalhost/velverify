package governance

import (
	"encoding/json"
	"time"

	"github.com/dhawalhost/wardseal/internal/oauthclient"
)

// OAuthClientResponse is the wire format for OAuth clients.
type OAuthClientResponse struct {
	ClientID      string   `json:"client_id"`
	TenantID      string   `json:"tenant_id"`
	ClientType    string   `json:"client_type"`
	Name          string   `json:"name"`
	Description   string   `json:"description,omitempty"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
}

func newOAuthClientResponse(client oauthclient.Client) OAuthClientResponse {
	resp := OAuthClientResponse{
		ClientID:      client.ClientID,
		TenantID:      client.TenantID,
		ClientType:    client.ClientType,
		Name:          client.Name,
		RedirectURIs:  append([]string(nil), client.RedirectURIs...),
		AllowedScopes: append([]string(nil), client.AllowedScopes...),
	}
	if client.Description.Valid {
		resp.Description = client.Description.String
	}
	return resp
}

type createOAuthClientRequest struct {
	ClientID      string   `json:"client_id"`
	Name          string   `json:"name"`
	Description   string   `json:"description"`
	ClientType    string   `json:"client_type"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
	ClientSecret  string   `json:"client_secret"`
}

type updateOAuthClientRequest struct {
	Name          *string  `json:"name"`
	Description   *string  `json:"description"`
	ClientType    *string  `json:"client_type"`
	RedirectURIs  []string `json:"redirect_uris"`
	AllowedScopes []string `json:"allowed_scopes"`
	ClientSecret  *string  `json:"client_secret"`
}

// Access Request types

type AccessRequest struct {
	ID            string          `json:"id"`
	TenantID      string          `json:"tenant_id"`
	RequesterID   string          `json:"requester_id"`
	RequesterType string          `json:"requester_type"` // user, workload
	ResourceType  string          `json:"resource_type"`
	ResourceID    string          `json:"resource_id"`
	Status        string          `json:"status"`
	Reason        string          `json:"reason"`
	Duration      string          `json:"duration,omitempty"` // e.g. "4h", "1d"
	CreatedAt     string          `json:"created_at"`         // ISO8601
	UpdatedAt     string          `json:"updated_at"`
	DeviceID      string          `json:"device_id,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

type CreateAccessRequest struct {
	RequesterID   string          `json:"requester_id,omitempty"`
	RequesterType string          `json:"requester_type,omitempty"` // Default: user
	ResourceType  string          `json:"resource_type"`
	ResourceID    string          `json:"resource_id"`
	Reason        string          `json:"reason"`
	Duration      string          `json:"duration,omitempty"` // "1h", "4h", "24h", etc.
	DeviceID      string          `json:"device_id,omitempty"`
	Metadata      json.RawMessage `json:"metadata,omitempty"`
}

type AccessRequestList struct {
	Requests []AccessRequest `json:"requests"`
}

type ApprovalDecision struct {
	Comment string `json:"comment"`
}

// IP Access Policy types

type IPPolicy struct {
	ID          string `json:"id"`
	TenantID    string `json:"tenant_id"`
	Type        string `json:"type"` // ALLOW, BLOCK
	CIDR        string `json:"cidr,omitempty"`
	CountryCode string `json:"country_code,omitempty"`
	Reason      string `json:"reason,omitempty"`
	CreatedAt   string `json:"created_at"`
}

type CreateIPPolicyRequest struct {
	Type        string `json:"type" binding:"required,oneof=ALLOW BLOCK"`
	CIDR        string `json:"cidr"`
	CountryCode string `json:"country_code"`
	Reason      string `json:"reason"`
}

// Safety Action types

type SafetyAction struct {
	ID         string          `json:"id" db:"id"`
	TenantID   string          `json:"tenant_id" db:"tenant_id"`
	ActionType string          `json:"action_type" db:"action_type"` // e.g., "revoke_all_access"
	TargetID   string          `json:"target_id" db:"target_id"`     // user_id
	Metadata   json.RawMessage `json:"metadata" db:"metadata"`       // stores org_ids or other context
	Status     string          `json:"status" db:"status"`           // pending, confirmed, rejected
	Reason     string          `json:"reason" db:"reason"`
	CreatedAt  time.Time       `json:"created_at" db:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at" db:"updated_at"`
}

type ProposeSafetyActionInput struct {
	ActionType string          `json:"action_type"`
	TargetID   string          `json:"target_id"`
	Metadata   json.RawMessage `json:"metadata"`
	Reason     string          `json:"reason"`
}

type ConfirmSafetyActionRequest struct {
	Comment string `json:"comment"`
}

// DashboardStats represents a snapshot of the governance landscape.
type DashboardStats struct {
	ActiveUsers      int            `json:"active_users"`
	TotalGroups      int            `json:"total_groups"`
	PendingRequests  int            `json:"pending_requests"`
	ActiveWorkloads  int            `json:"active_workloads"`
	RiskProfile      map[string]int `json:"risk_profile"`  // Level -> Count
	HygieneScore     int            `json:"hygiene_score"` // 0-100
	ConnectedOrgs    int            `json:"connected_orgs"`
	ActiveIPPolicies int            `json:"active_ip_policies"`
}

// WorkloadResponse is the wire format for machine identities.
type WorkloadResponse struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	ServiceHandle string `json:"service_handle"`
	Status        string `json:"status"`
	LastUsedAt    string `json:"last_used_at,omitempty"`
}
