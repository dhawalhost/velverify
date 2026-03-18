package governance

import "github.com/dhawalhost/wardseal/internal/oauthclient"

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
	ID           string `json:"id"`
	TenantID     string `json:"tenant_id"`
	RequesterID  string `json:"requester_id"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Status       string `json:"status"`
	Reason       string `json:"reason"`
	CreatedAt    string `json:"created_at"` // ISO8601
	UpdatedAt    string `json:"updated_at"`
}

type CreateAccessRequest struct {
	RequesterID  string `json:"requester_id,omitempty"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Reason       string `json:"reason"`
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
