package auth

// LoginRequest holds the request parameters for the Login endpoint.
type LoginRequest struct {
	Username string `json:"username" validate:"required,email"`
	Password string `json:"password" validate:"required,min=8"`
}

// LoginResponse holds the response values for the Login endpoint.
type LoginResponse struct {
	Token string `json:"token"`
}

// AuthorizeRequest holds the request parameters for the Authorize endpoint.
type AuthorizeRequest struct {
	ResponseType        string `form:"response_type" json:"response_type" validate:"required,eq=code"`
	ClientID            string `form:"client_id" json:"client_id" validate:"required"`
	RedirectURI         string `form:"redirect_uri" json:"redirect_uri" validate:"required,url"`
	Scope               string `form:"scope" json:"scope" validate:"required"`
	State               string `form:"state" json:"state"`
	CodeChallenge       string `form:"code_challenge" json:"code_challenge" validate:"required"`
	CodeChallengeMethod string `form:"code_challenge_method" json:"code_challenge_method" validate:"omitempty,oneof=S256"`
}

// AuthorizeResponse holds the response values for the Authorize endpoint.
type AuthorizeResponse struct {
	RedirectURI string `json:"redirect_uri"`
}

// TokenRequest holds the request parameters for the Token endpoint.
type TokenRequest struct {
	GrantType    string `form:"grant_type" json:"grant_type" validate:"required,eq=authorization_code"`
	Code         string `form:"code" json:"code" validate:"required"`
	RedirectURI  string `form:"redirect_uri" json:"redirect_uri" validate:"required,url"`
	ClientID     string `form:"client_id" json:"client_id" validate:"required"`
	CodeVerifier string `form:"code_verifier" json:"code_verifier" validate:"required,min=43,max=128"`
}

// TokenResponse holds the response values for the Token endpoint.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token,omitempty"`
}
