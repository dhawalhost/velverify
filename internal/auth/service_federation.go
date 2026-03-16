package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"

	"strings"

	"github.com/dhawalhost/wardseal/pkg/middleware"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// SocialLogin handles the login/registration via an external provider.
func (s *authService) SocialLogin(ctx context.Context, req SocialLoginRequest) (TokenResponse, error) {
	tenantID, err := middleware.TenantIDFromContext(ctx)
	if err != nil {
		return TokenResponse{}, err
	}

	// 1. Validate Provider & Exchange Token
	ssoProvider, err := s.ssoProviderStore.GetByName(ctx, tenantID, req.Provider)
	if err != nil {
		return TokenResponse{}, err
	}
	if ssoProvider == nil {
		return TokenResponse{}, &Error{"invalid_request", fmt.Sprintf("provider '%s' not configured", req.Provider)}
	}

	// Default to generic OIDC if not specified
	authURL := ""
	tokenURL := ""
	userInfoURL := ""

	if ssoProvider.OIDCIssuerURL != nil && *ssoProvider.OIDCIssuerURL != "" {
		// Basic assumption for standard OIDC
		issuer := strings.TrimRight(*ssoProvider.OIDCIssuerURL, "/")
		authURL = issuer + "/authorize"
		tokenURL = issuer + "/token"
		userInfoURL = issuer + "/userinfo"

		// Handle Google specifically if needed, but Google follows OIDC usually
		if req.Provider == "google" {
			userInfoURL = "https://www.googleapis.com/oauth2/v3/userinfo"
		}
	} else {
		// Fallback for known providers if URL not set (unlikely if configured correctly)
		return TokenResponse{}, &Error{"invalid_configuration", "sso provider issuer url missing"}
	}

	clientID := ""
	if ssoProvider.OIDCClientID != nil {
		clientID = strings.TrimSpace(*ssoProvider.OIDCClientID)
	}

	conf := &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: string(ssoProvider.OIDCClientSecret),
		// RedirectURL:  req.RedirectURI, // Need to verify if request has it
		Scopes: []string{"openid", "profile", "email"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  authURL,
			TokenURL: tokenURL,
		},
	}

	if ssoProvider.OIDCScopes != nil && *ssoProvider.OIDCScopes != "" {
		conf.Scopes = strings.Split(*ssoProvider.OIDCScopes, " ")
	}

	token, err := conf.Exchange(ctx, req.Code)
	if err != nil {
		return TokenResponse{}, &Error{"invalid_grant", "failed to exchange code: " + err.Error()}
	}

	client := conf.Client(ctx, token)
	resp, err := client.Get(userInfoURL)
	if err != nil {
		return TokenResponse{}, &Error{"invalid_request", "failed to fetch user profile"}
	}
	defer func() { _ = resp.Body.Close() }()

	var idTokenClaims struct {
		Email string `json:"email"`
		Sub   string `json:"sub"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&idTokenClaims); err != nil {
		return TokenResponse{}, &Error{"server_error", "failed to decode user profile"}
	}

	profile := struct {
		Email      string
		ExternalID string
		Name       string
	}{
		Email:      idTokenClaims.Email,
		ExternalID: idTokenClaims.Sub,
		Name:       idTokenClaims.Name,
	}

	if profile.Email == "" || profile.ExternalID == "" {
		return TokenResponse{}, &Error{"invalid_request", "no email or sub in provider response"}
	}

	// 2. Check for existing link
	existingParams, err := s.federationStore.Get(ctx, tenantID, req.Provider, profile.ExternalID)
	if err != nil {
		return TokenResponse{}, err
	}

	var userID string

	switch {
	case existingParams != nil:
		// Link exists -> Login
		userID = existingParams.IdentityID //nolint:ineffassign // Used in issueTokens below

	default:
		// No link -> Check if user exists by email (JIT / Auto-Link)
		// We need to call Directory Service to find user by email
		// Note: Directory Service abstraction is needed here.
		// authService has `Login` which calls `verifyCredentials`.
		// We need a `GetUserByEmail` method exposed on Directory Service or via HTTP.

		// For now, let's assume we can create/provision or find via HTTP.
		// Since we don't have a direct `FindUserByEmail` RPC client, we'll implement a helper.

		user, err := s.findUserByEmail(ctx, tenantID, profile.Email)
		if err != nil {
			// Error looking up user
			return TokenResponse{}, err
		}

		if user != nil {
			// User exists -> Create Link
			userID = user.ID
			profileDataBytes, _ := json.Marshal(map[string]interface{}{"email": profile.Email})
			if err := s.federationStore.Create(ctx, FederatedIdentity{
				IdentityID:  userID,
				TenantID:    tenantID,
				Provider:    req.Provider,
				ExternalID:  profile.ExternalID,
				ProfileData: JSON(profileDataBytes),
			}); err != nil {
				return TokenResponse{}, err
			}
		} else {
			// User does not exist -> JIT Provision
			// 1. Create User in Directory
			newUser, err := s.provisionUser(ctx, tenantID, profile.Email, profile.Name)
			if err != nil {
				return TokenResponse{}, err
			}
			userID = newUser.ID

			// 2. Create Link
			profileDataBytes, _ := json.Marshal(map[string]interface{}{"email": profile.Email})
			if err := s.federationStore.Create(ctx, FederatedIdentity{
				IdentityID:  userID,
				TenantID:    tenantID,
				Provider:    req.Provider,
				ExternalID:  profile.ExternalID,
				ProfileData: JSON(profileDataBytes),
			}); err != nil {
				return TokenResponse{}, err
			}
		}
	}

	// 3. Issue Tokens (Same as Login)
	// We assume minimal scope for now or default
	scope := "openid profile email"
	tokenClientID := socialTokenClientID(req.Provider, clientID)

	return s.issueTokensWithoutRefresh(tenantID, tokenClientID, scope, userID, "")
}

func socialTokenClientID(provider, oidcClientID string) string {
	if oidcClientID != "" {
		return oidcClientID
	}

	provider = strings.TrimSpace(provider)
	if provider == "" {
		return "social:unknown"
	}

	return fmt.Sprintf("social:%s", provider)
}

// Helper structs for internal calls
type directoryUser struct {
	ID    string `json:"id"`
	Email string `json:"email"`
}

// findUserByEmail calls Directory service to find a user
func (s *authService) findUserByEmail(ctx context.Context, tenantID, email string) (*directoryUser, error) {
	// Call SCIM Service: GET /scim/v2/Users?filter=userName eq "email"
	// We use s.directoryServiceURL + /scim/v2/Users

	filter := fmt.Sprintf("userName eq \"%s\"", email)
	u, err := url.Parse(fmt.Sprintf("%s/scim/v2/Users", s.directoryServiceURL))
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("filter", filter)
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set(middleware.DefaultTenantHeader, tenantID)
	// Internal Auth for SCIM requires Bearer Token format
	if s.serviceAuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.serviceAuthToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		// Log or return error
		zap.L().Warn("Failed to search user by email", zap.Int("status", resp.StatusCode))
		return nil, nil // Treat as not found or error
	}

	// Parse SCIM List Response
	var listResp struct {
		TotalResults int `json:"totalResults"`
		Resources    []struct {
			ID       string `json:"id"`
			UserName string `json:"userName"`
		} `json:"Resources"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return nil, err
	}

	if listResp.TotalResults > 0 && len(listResp.Resources) > 0 {
		return &directoryUser{
			ID:    listResp.Resources[0].ID,
			Email: listResp.Resources[0].UserName,
		}, nil
	}

	return nil, nil
}

func (s *authService) provisionUser(ctx context.Context, tenantID, email, name string) (*directoryUser, error) {
	// Call SCIM Service: POST /scim/v2/Users
	u := fmt.Sprintf("%s/scim/v2/Users", s.directoryServiceURL)

	// Construct SCIM JSON
	// Very basic SCIM payload
	// Note: We need to set a dummy password or handle passwordless creation if directory supports it.
	// Our CreateUser implementation expects a password.
	// We'll generate a random complex password for federated users since they won't use it directly.

	randomPwd, _ := generateAuthorizationCode() // Reusing random string gen, 32 bytes base64 is strong enough

	scimUser := map[string]interface{}{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": email,
		"password": randomPwd,
		"active":   true,
		"name": map[string]string{
			"formatted":  name,
			"familyName": name, // fallback
		},
		"emails": []map[string]interface{}{
			{
				"value":   email,
				"primary": true,
				"type":    "work",
			},
		},
	}

	bodyBytes, _ := json.Marshal(scimUser)
	req, err := http.NewRequestWithContext(ctx, "POST", u, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/scim+json")
	req.Header.Set(middleware.DefaultTenantHeader, tenantID)
	// Internal Auth for SCIM requires Bearer Token format
	if s.serviceAuthToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.serviceAuthToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("failed to provision user, status: %d", resp.StatusCode)
	}

	var createdUser struct {
		ID       string `json:"id"`
		UserName string `json:"userName"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createdUser); err != nil {
		return nil, err
	}

	return &directoryUser{
		ID:    createdUser.ID,
		Email: createdUser.UserName,
	}, nil
}
