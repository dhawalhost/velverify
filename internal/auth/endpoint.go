package auth

// LoginRequest holds the request parameters for the Login endpoint.
type LoginRequest struct {
	Username string `json:"username" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// LoginResponse holds the response values for the Login endpoint.
type LoginResponse struct {
	Token      string   `json:"token"`
	Roles      []string `json:"roles,omitempty"`
	TenantID   string   `json:"tenant_id,omitempty"`
	TenantSlug string   `json:"tenant_slug,omitempty"`
}

// AuthorizeRequest holds the request parameters for the Authorize endpoint.
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" json:"response_type" validate:"required,eq=code"`
	ClientID            string `form:"client_id" json:"client_id" validate:"required"`
	RedirectURI         string `form:"redirect_uri" json:"redirect_uri" validate:"required,url"`
	Scope               string `form:"scope" json:"scope" validate:"required"`
	State               string `form:"state" json:"state"`
	Nonce               string `form:"nonce" json:"nonce"`
	CodeChallenge       string `form:"code_challenge" json:"code_challenge" validate:"required"`
	CodeChallengeMethod string `form:"code_challenge_method" json:"code_challenge_method" validate:"omitempty,oneof=S256"`
}

// AuthorizeResponse holds the response values for the Authorize endpoint.
type AuthorizeResponse struct {
	RedirectURI string `json:"redirect_uri"`
}

// TokenRequest holds the request parameters for the Token endpoint.
// Fields are conditionally required based on grant_type.
type TokenRequest struct {
	GrantType string `form:"grant_type" json:"grant_type" validate:"required,oneof=authorization_code client_credentials refresh_token"`

	// For authorization_code grant
	Code         string `form:"code" json:"code"`
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri"`
	CodeVerifier string `form:"code_verifier" json:"code_verifier"`

	// Common fields
	ClientID     string `form:"client_id" json:"client_id"`
	ClientSecret string `form:"client_secret" json:"client_secret"`
	Scope        string `form:"scope" json:"scope"`

	// For refresh_token grant
	RefreshToken string `form:"refresh_token" json:"refresh_token"`
}

// TokenResponse holds the response values for the Token endpoint.
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	IDToken      string `json:"id_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// IntrospectRequest holds the request parameters for the Introspect endpoint.
type IntrospectRequest struct {
	Token         string `form:"token" json:"token" validate:"required"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint"`
}

// IntrospectResponse holds the response values for the Introspect endpoint.
type IntrospectResponse struct {
	Active    bool   `json:"active"`
	Scope     string `json:"scope,omitempty"`
	ClientID  string `json:"client_id,omitempty"`
	Username  string `json:"username,omitempty"`
	TokenType string `json:"token_type,omitempty"`
	Exp       int64  `json:"exp,omitempty"`
	Iat       int64  `json:"iat,omitempty"`
	Sub       string `json:"sub,omitempty"`
	Aud       string `json:"aud,omitempty"`
	Iss       string `json:"iss,omitempty"`
	TenantID  string `json:"tenant_id,omitempty"`
}

// RevokeRequest holds the request parameters for the Revoke endpoint.
type RevokeRequest struct {
	Token         string `form:"token" json:"token" validate:"required"`
	TokenTypeHint string `form:"token_type_hint" json:"token_type_hint"`
}

// OpenIDConfiguration holds the OIDC discovery metadata.
type OpenIDConfiguration struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JwksURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	ClaimsSupported                   []string `json:"claims_supported,omitempty"`
}
