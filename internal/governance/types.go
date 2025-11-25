package governance

import "github.com/dhawalhost/velverify/internal/oauthclients"

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

func newOAuthClientResponse(client oauthclients.Client) OAuthClientResponse {
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
