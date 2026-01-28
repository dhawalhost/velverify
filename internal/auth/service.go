package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/saml"
	"github.com/dhawalhost/wardseal/pkg/kms"
	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-jose/go-jose.v2"
)

// Service defines the interface for the auth service.
type Service interface {
	Login(ctx context.Context, username, password, deviceID, userAgent, ip, clientOSVersion string) (string, error)
	Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, error)
	Token(ctx context.Context, req TokenRequest) (TokenResponse, error)
	Introspect(ctx context.Context, req IntrospectRequest) (IntrospectResponse, error)
	Revoke(ctx context.Context, req RevokeRequest) error
	SAML() *saml.Provider
	JWKS() jose.JSONWebKeySet
	Device() DeviceStore
	Signal() SignalStore
	WebAuthn() *webauthn.WebAuthn
	// WebAuthn Methods
	BeginWebAuthnRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, *webauthn.SessionData, error)
	FinishWebAuthnRegistration(ctx context.Context, userID string, session webauthn.SessionData, req *http.Request) error
	BeginWebAuthnLogin(ctx context.Context, userID string) (*protocol.CredentialAssertion, *webauthn.SessionData, error)
	FinishWebAuthnLogin(ctx context.Context, userID string, session webauthn.SessionData, req *http.Request) (string, error)
	// Social Login
	SocialLogin(ctx context.Context, req SocialLoginRequest) (TokenResponse, error)
	// Branding
	GetBranding(ctx context.Context, tenantID string) (BrandingConfig, error)
	UpdateBranding(ctx context.Context, config BrandingConfig) error

	// Client Management for Portal
	ListClients(ctx context.Context, tenantID string) ([]oauthclient.Client, error)

	// User Self-Update
	UpdateUserSelf(ctx context.Context, tenantID, userID string, updates map[string]interface{}) error

	// TOTP MFA
	TOTP() TOTPStore

	// User Lookup
	LookupUser(ctx context.Context, tenantID, email string) (LookupResult, error)
	// SignUp
	SignUp(ctx context.Context, email, password, companyName, plan string) (string, string, error)

	// System Setup
	GetSystemSetupStatus(ctx context.Context) (bool, error)
	PerformSystemSetup(ctx context.Context, email, password string) (string, error)
}

type LookupResult struct {
	UserID          string `json:"user_id"`
	WebAuthnEnabled bool   `json:"webauthn_enabled"`
	TenantID        string `json:"tenant_id,omitempty"`
}

type authService struct {
	directoryServiceURL string
	httpClient          *http.Client
	signer              kms.Signer
	serviceAuthHeader   string
	serviceAuthToken    string
	codeStore           AuthorizationCodeStore
	refreshTokenStore   RefreshTokenStore
	revokedTokens       RevocationStore
	clients             map[clientKey]ClientConfig
	clientStore         oauthclient.Store
	samlProvider        *saml.Provider
	deviceStore         DeviceStore
	signalStore         SignalStore
	riskEngine          *RiskEngine
	webAuthn            *webauthn.WebAuthn
	webAuthnStore       WebAuthnRepository
	brandingStore       BrandingStore
	federationStore     FederationStore
	totpStore           TOTPStore
	ssoProviderStore    SSOProviderStore
	deploymentMode      string
}

// AuthorizationCodeStore defines the interface for storing authorization codes.
type AuthorizationCodeStore interface {
	Save(ctx context.Context, code authorizationCode) error
	Get(ctx context.Context, code string) (authorizationCode, bool, error)
	Delete(ctx context.Context, code string) error
}

// RefreshTokenStore defines the interface for storing refresh tokens.
type RefreshTokenStore interface {
	Save(ctx context.Context, entry refreshTokenEntry) error
	Get(ctx context.Context, token string) (refreshTokenEntry, bool, error)
	Delete(ctx context.Context, token string) error
}

// RevocationStore defines the interface for token revocation.
type RevocationStore interface {
	Revoke(ctx context.Context, token string) error
	IsRevoked(ctx context.Context, token string) (bool, error)
}

// Config captures the settings for the auth service.
type Config struct {
	DirectoryServiceURL string
	ServiceAuthToken    string
	ServiceAuthHeader   string
	Clients             []ClientConfig
	ClientStore         oauthclient.Store
	SAMLStore           *saml.Store
	DeviceStore         DeviceStore
	SignalStore         SignalStore
	WebAuthnStore       WebAuthnRepository
	BrandingStore       BrandingStore
	FederationStore     FederationStore
	BaseURL             string
	// Persistent stores (optional, defaults to in-memory if not provided)
	CodeStore        AuthorizationCodeStore
	RefreshStore     RefreshTokenStore
	RevocationStore  RevocationStore
	TOTPStore        TOTPStore
	SSOProviderStore SSOProviderStore
	// KMS Signer (optional, defaults to ephemeral local signer)
	Signer kms.Signer
	// Deployment Mode: "saas" or "selfhost" (default)
	DeploymentMode string
}

// NewService creates a new auth service.
func NewService(cfg Config) (Service, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("base URL is required")
	}
	if cfg.DirectoryServiceURL == "" {
		return nil, errors.New("directory service URL is required")
	}
	header := cfg.ServiceAuthHeader
	if header == "" {
		header = middleware.DefaultServiceAuthHeader
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	// Create self-signed certificate for SAML
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "wardseal-idp",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, err
	}

	samlProvider, err := saml.NewProvider(saml.Config{
		BaseURL:     cfg.BaseURL,
		Certificate: cert,
		PrivateKey:  privateKey,
		Logger:      zap.L(), // Use global logger for now, ideally passed in config
		Store:       cfg.SAMLStore,
	})
	if err != nil {
		return nil, err
	}

	// WebAuthn Init
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "WardSeal Identity",
		RPID:          "localhost",                                    // TODO: Configurable
		RPOrigins:     []string{cfg.BaseURL, "http://localhost:5173"}, // Admin UI origin
	})
	if err != nil {
		return nil, err
	}

	var clientMap map[clientKey]ClientConfig
	if cfg.ClientStore == nil {
		var err error
		clientMap, err = buildClientMap(cfg.Clients)
		if err != nil {
			return nil, err
		}
	} else if len(cfg.Clients) > 0 {
		return nil, errors.New("both ClientStore and static Clients provided; choose one source")
	}

	// Initialize stores - use SQL if provided, otherwise fall back to in-memory
	var codeStore AuthorizationCodeStore = newAuthorizationCodeStore()
	if cfg.CodeStore != nil {
		codeStore = cfg.CodeStore
	}
	var refreshStore RefreshTokenStore = newRefreshTokenStore()
	if cfg.RefreshStore != nil {
		refreshStore = cfg.RefreshStore
	}
	var revocationStore RevocationStore = newTokenRevocationStore()
	if cfg.RevocationStore != nil {
		revocationStore = cfg.RevocationStore
	}

	// Initialize KMS Signer - use provided signer or create ephemeral local signer
	signer := cfg.Signer
	if signer == nil {
		var err error
		signer, err = kms.NewLocalSigner("", "")
		if err != nil {
			return nil, fmt.Errorf("failed to create ephemeral signer: %w", err)
		}
	}

	deploymentMode := cfg.DeploymentMode
	if deploymentMode == "" {
		deploymentMode = "selfhost"
	}

	return &authService{
		directoryServiceURL: cfg.DirectoryServiceURL,
		httpClient:          &http.Client{Timeout: 5 * time.Second},
		signer:              signer,
		serviceAuthHeader:   header,
		serviceAuthToken:    cfg.ServiceAuthToken,
		codeStore:           codeStore,
		refreshTokenStore:   refreshStore,
		revokedTokens:       revocationStore,
		clients:             clientMap,
		clientStore:         cfg.ClientStore,
		samlProvider:        samlProvider,
		deviceStore:         cfg.DeviceStore,
		signalStore:         cfg.SignalStore,
		riskEngine:          NewRiskEngine(cfg.DeviceStore, cfg.SignalStore, zap.L()),
		webAuthn:            w,
		webAuthnStore:       cfg.WebAuthnStore,
		federationStore:     cfg.FederationStore,
		totpStore:           cfg.TOTPStore,
		brandingStore:       cfg.BrandingStore,
		ssoProviderStore:    cfg.SSOProviderStore,
		deploymentMode:      deploymentMode,
	}, nil
}

func (s *authService) Login(ctx context.Context, username, password, deviceID, userAgent, ip, clientOSVersion string) (string, error) {
	tenantID, err := middleware.TenantIDFromContext(ctx)
	if err != nil {
		return "", err
	}
	payload := struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}{Email: username, Password: password}
	body, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	// 1. Ask the directory service to verify the credentials.
	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/internal/credentials/verify", s.directoryServiceURL), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, tenantID)
	if s.serviceAuthToken != "" {
		req.Header.Set(s.serviceAuthHeader, s.serviceAuthToken)
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return "", ErrInvalidCredentials
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("directory service returned status %d", resp.StatusCode)
	}

	var userResp struct {
		User struct {
			ID    string `json:"id"`
			Email string `json:"email"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return "", err
	}

	// 2. Risk Evaluation
	risk, err := s.riskEngine.Evaluate(ctx, userResp.User.ID, deviceID, ip)
	if err != nil {
		// Log error but maybe fail open or closed?
		// Let's fail open (allow) but log error for MVP, or treat as medium risk.
		zap.L().Error("Risk evaluation failed", zap.Error(err))
	} else {
		if risk.Level == RiskLevelHigh {
			zap.L().Warn("Login blocked due to high risk",
				zap.String("user_id", userResp.User.ID),
				zap.Int("score", risk.Score),
				zap.Strings("factors", risk.Factors))
			return "", &Error{"access_denied", "login blocked due to security risk"}
		}
	}

	// 3. Register/Update Device
	if deviceID != "" {
		osName, osVersion := parseUserAgent(userAgent)
		if clientOSVersion != "" {
			// Trust the client's high-entropy version if provided
			// Note: We might want to normalize it, but detailed version is better than generic
			osVersion = clientOSVersion
		}
		if err := s.deviceStore.Register(ctx, &Device{
			TenantID:         tenantID,
			UserID:           userResp.User.ID,
			DeviceIdentifier: deviceID,
			OS:               osName,
			OSVersion:        osVersion,
			IsManaged:        false,
			IsCompliant:      true, // Default
		}); err != nil {
			// Don't block login on device reg failure, just log
			zap.L().Warn("Failed to register device during login", zap.Error(err))
		}
	}

	// 4. Generate a JWT.
	claims := jwt.MapClaims{
		"sub":    userResp.User.ID,
		"iss":    "identity-platform",
		"aud":    "client-app",
		"exp":    time.Now().Add(time.Hour * 1).Unix(),
		"iat":    time.Now().Unix(),
		"scope":  "openid profile email",
		"tenant": tenantID,
	}

	signedToken, err := s.signer.Sign(claims)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

func parseUserAgent(ua string) (string, string) {
	uaLower := strings.ToLower(ua)

	if strings.Contains(uaLower, "macintosh") || strings.Contains(uaLower, "mac os") {
		re := regexp.MustCompile(`mac os x ([\d_]+)`)
		matches := re.FindStringSubmatch(uaLower)
		version := "Unknown"
		if len(matches) > 1 {
			version = strings.ReplaceAll(matches[1], "_", ".")
		}
		return "macOS", version
	}

	if strings.Contains(uaLower, "windows") {
		re := regexp.MustCompile(`windows nt ([\d.]+)`)
		matches := re.FindStringSubmatch(uaLower)
		version := "Unknown"
		if len(matches) > 1 {
			version = matches[1]
		}
		return "Windows", version
	}

	if strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipad") {
		re := regexp.MustCompile(`os ([\d_]+) like mac os x`)
		matches := re.FindStringSubmatch(uaLower)
		version := "Unknown"
		if len(matches) > 1 {
			version = strings.ReplaceAll(matches[1], "_", ".")
		}
		return "iOS", version
	}

	if strings.Contains(uaLower, "android") {
		re := regexp.MustCompile(`android ([\d.]+)`)
		matches := re.FindStringSubmatch(uaLower)
		version := "Unknown"
		if len(matches) > 1 {
			version = matches[1]
		}
		return "Android", version
	}

	if strings.Contains(uaLower, "linux") {
		return "Linux", "Unknown"
	}

	return "Unknown", "Unknown"
}

func (s *authService) LookupUser(ctx context.Context, tenantID, email string) (LookupResult, error) {
	// 0. Tenant Discovery (if not provided)
	if tenantID == "" {
		req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/internal/discover", s.directoryServiceURL), nil)
		if err != nil {
			return LookupResult{}, err
		}
		q := req.URL.Query()
		q.Add("email", email)
		req.URL.RawQuery = q.Encode()

		if s.serviceAuthToken != "" {
			req.Header.Set(s.serviceAuthHeader, s.serviceAuthToken)
		}

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return LookupResult{}, fmt.Errorf("failed to discover tenant: %w", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode == http.StatusNotFound {
			return LookupResult{}, errors.New("user not found (or tenant could not be discovered)")
		}
		if resp.StatusCode != http.StatusOK {
			return LookupResult{}, fmt.Errorf("directory discovery returned status %d", resp.StatusCode)
		}

		var discoveryResp struct {
			TenantID string `json:"tenant_id"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&discoveryResp); err != nil {
			return LookupResult{}, fmt.Errorf("failed to decode discovery response: %w", err)
		}
		tenantID = discoveryResp.TenantID
	}

	// 1. Call Directory Service to resolve email to UserID
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/users", s.directoryServiceURL), nil)
	if err != nil {
		return LookupResult{}, err
	}
	q := req.URL.Query()
	q.Add("email", email)
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, tenantID)
	if s.serviceAuthToken != "" {
		req.Header.Set(s.serviceAuthHeader, s.serviceAuthToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return LookupResult{}, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return LookupResult{}, errors.New("user not found")
	}
	if resp.StatusCode != http.StatusOK {
		return LookupResult{}, fmt.Errorf("directory service returned status %d", resp.StatusCode)
	}

	var userResp struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return LookupResult{}, err
	}

	// 2. Check if WebAuthn credentials exist
	creds, err := s.webAuthnStore.ListCredentials(ctx, userResp.User.ID)
	if err != nil {
		// Log error but assume false? Or fail?
		zap.L().Warn("Failed to list webauthn credentials during lookup", zap.Error(err))
		// default to false
	}

	return LookupResult{
		UserID:          userResp.User.ID,
		WebAuthnEnabled: len(creds) > 0,
		TenantID:        tenantID, // Return the discovered tenant ID
	}, nil
}

// JWKS returns the JSON Web Key Set.
func (s *authService) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       s.signer.PublicKey(),
				KeyID:     s.signer.KeyID(),
				Algorithm: s.signer.Algorithm(),
				Use:       "sig",
			},
		},
	}
}

func (s *authService) Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, error) {
	tenantID, err := middleware.TenantIDFromContext(ctx)
	if err != nil {
		return AuthorizeResponse{}, err
	}
	client, err := s.resolveClient(ctx, tenantID, req.ClientID)
	if err != nil {
		return AuthorizeResponse{}, err
	}
	if client.TenantID != tenantID {
		return AuthorizeResponse{}, ErrInvalidClient
	}
	if !client.allowsRedirect(req.RedirectURI) {
		return AuthorizeResponse{}, ErrInvalidRedirectURI
	}
	if err := client.validateScopes(req.Scope); err != nil {
		return AuthorizeResponse{}, newInvalidScopeError(err.Error())
	}
	if req.CodeChallenge == "" {
		return AuthorizeResponse{}, ErrMissingCodeChallenge
	}
	method := req.CodeChallengeMethod
	if method == "" {
		method = "S256"
	}
	if method != "S256" {
		return AuthorizeResponse{}, ErrInvalidCodeChallengeMethod
	}
	code, err := generateAuthorizationCode()
	if err != nil {
		return AuthorizeResponse{}, err
	}
	expiresAt := time.Now().Add(5 * time.Minute)
	entry := authorizationCode{
		Code:                code,
		ClientID:            req.ClientID,
		RedirectURI:         req.RedirectURI,
		Scope:               req.Scope,
		TenantID:            tenantID,
		CodeChallenge:       req.CodeChallenge,
		CodeChallengeMethod: method,
		ExpiresAt:           expiresAt,
	}
	_ = s.codeStore.Save(ctx, entry)
	redirectURI, err := buildAuthorizationRedirect(req.RedirectURI, code, req.State)
	if err != nil {
		return AuthorizeResponse{}, err
	}
	return AuthorizeResponse{RedirectURI: redirectURI}, nil
}

func (s *authService) Token(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	tenantID, err := middleware.TenantIDFromContext(ctx)
	if err != nil {
		return TokenResponse{}, err
	}

	switch req.GrantType {
	case "authorization_code":
		return s.handleAuthorizationCodeGrant(ctx, tenantID, req)
	case "client_credentials":
		return s.handleClientCredentialsGrant(ctx, tenantID, req)
	case "refresh_token":
		return s.handleRefreshTokenGrant(ctx, tenantID, req)
	default:
		return TokenResponse{}, ErrUnsupportedGrantType
	}
}

func (s *authService) handleAuthorizationCodeGrant(ctx context.Context, tenantID string, req TokenRequest) (TokenResponse, error) {
	if req.ClientID == "" || req.Code == "" || req.RedirectURI == "" || req.CodeVerifier == "" {
		return TokenResponse{}, &Error{"invalid_request", "missing required parameters for authorization_code grant"}
	}

	client, err := s.resolveClient(ctx, tenantID, req.ClientID)
	if err != nil {
		return TokenResponse{}, err
	}
	if !client.allowsRedirect(req.RedirectURI) {
		return TokenResponse{}, ErrInvalidRedirectURI
	}
	code, found, err := s.codeStore.Get(ctx, req.Code)
	if err != nil {
		return TokenResponse{}, err
	}
	if !found || time.Now().After(code.ExpiresAt) {
		return TokenResponse{}, ErrInvalidAuthorizationCode
	}
	if code.ClientID != req.ClientID || code.RedirectURI != req.RedirectURI || code.TenantID != tenantID {
		return TokenResponse{}, ErrInvalidAuthorizationCode
	}
	if err := verifyCodeChallenge(code.CodeChallenge, code.CodeChallengeMethod, req.CodeVerifier); err != nil {
		return TokenResponse{}, err
	}
	_ = s.codeStore.Delete(ctx, req.Code)

	return s.issueTokens(ctx, tenantID, req.ClientID, code.Scope, "user")
}

func (s *authService) handleClientCredentialsGrant(ctx context.Context, tenantID string, req TokenRequest) (TokenResponse, error) {
	if req.ClientID == "" {
		return TokenResponse{}, &Error{"invalid_request", "client_id is required"}
	}

	client, err := s.resolveClient(ctx, tenantID, req.ClientID)
	if err != nil {
		return TokenResponse{}, err
	}

	// Client credentials flow requires a confidential client
	if client.ClientType != "confidential" {
		return TokenResponse{}, &Error{"unauthorized_client", "client_credentials grant requires a confidential client"}
	}

	// Validate client secret
	if req.ClientSecret == "" {
		return TokenResponse{}, &Error{"invalid_request", "client_secret is required for confidential clients"}
	}

	// Get secret hash from store and verify
	if s.clientStore != nil {
		record, err := s.clientStore.GetClient(ctx, tenantID, req.ClientID)
		if err != nil {
			return TokenResponse{}, ErrInvalidClient
		}
		if len(record.ClientSecretHash) == 0 {
			return TokenResponse{}, &Error{"invalid_client", "client has no secret configured"}
		}
		if err := verifyClientSecret(req.ClientSecret, record.ClientSecretHash); err != nil {
			return TokenResponse{}, &Error{"invalid_client", "invalid client secret"}
		}
	} else {
		// Static clients don't have secrets in this implementation
		return TokenResponse{}, &Error{"invalid_client", "client_credentials requires database-backed clients"}
	}

	// Determine scopes - use requested or default to client's allowed scopes
	scope := req.Scope
	if scope == "" {
		scope = strings.Join(client.AllowedScopes, " ")
	} else {
		if err := client.validateScopes(scope); err != nil {
			return TokenResponse{}, newInvalidScopeError(err.Error())
		}
	}

	// Issue access token only (no refresh token for client_credentials per RFC 6749)
	accessToken, err := s.generateAccessToken(tenantID, req.ClientID, scope, "client")
	if err != nil {
		return TokenResponse{}, err
	}

	return TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       scope,
	}, nil
}

func (s *authService) handleRefreshTokenGrant(ctx context.Context, tenantID string, req TokenRequest) (TokenResponse, error) {
	if req.RefreshToken == "" {
		return TokenResponse{}, &Error{"invalid_request", "refresh_token is required"}
	}

	// Check if refresh token is revoked
	revoked, err := s.revokedTokens.IsRevoked(ctx, req.RefreshToken)
	if err != nil {
		return TokenResponse{}, err
	}
	if revoked {
		return TokenResponse{}, &Error{"invalid_grant", "refresh token has been revoked"}
	}

	// Retrieve stored refresh token
	stored, found, err := s.refreshTokenStore.Get(ctx, req.RefreshToken)
	if err != nil {
		return TokenResponse{}, err
	}
	if !found || time.Now().After(stored.ExpiresAt) {
		return TokenResponse{}, &Error{"invalid_grant", "refresh token is invalid or expired"}
	}

	// Verify tenant matches
	if stored.TenantID != tenantID {
		return TokenResponse{}, &Error{"invalid_grant", "refresh token tenant mismatch"}
	}

	// Rotate refresh token - delete old and issue new
	_ = s.refreshTokenStore.Delete(ctx, req.RefreshToken)

	return s.issueTokens(ctx, tenantID, stored.ClientID, stored.Scope, stored.SubjectType)
}

func (s *authService) issueTokens(ctx context.Context, tenantID, clientID, scope, subjectType string) (TokenResponse, error) {
	accessToken, err := s.generateAccessToken(tenantID, clientID, scope, subjectType)
	if err != nil {
		return TokenResponse{}, err
	}

	refreshToken, err := s.generateRefreshToken(ctx, tenantID, clientID, scope, subjectType)
	if err != nil {
		return TokenResponse{}, err
	}

	return TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        scope,
	}, nil
}

func (s *authService) generateAccessToken(tenantID, clientID, scope, subjectType string) (string, error) {
	claims := jwt.MapClaims{
		"sub":          clientID,
		"iss":          "identity-platform",
		"aud":          "client-app",
		"exp":          time.Now().Add(time.Hour * 1).Unix(),
		"iat":          time.Now().Unix(),
		"scope":        scope,
		"tenant":       tenantID,
		"subject_type": subjectType,
	}

	return s.signer.Sign(claims)
}

func (s *authService) generateRefreshToken(ctx context.Context, tenantID, clientID, scope, subjectType string) (string, error) {
	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		return "", err
	}
	refreshToken := base64.RawURLEncoding.EncodeToString(tokenBytes)

	// Store refresh token with 7-day expiry
	err := s.refreshTokenStore.Save(ctx, refreshTokenEntry{
		Token:       refreshToken,
		ClientID:    clientID,
		TenantID:    tenantID,
		Scope:       scope,
		SubjectType: subjectType,
		ExpiresAt:   time.Now().Add(7 * 24 * time.Hour),
	})
	if err != nil {
		return "", err
	}

	return refreshToken, nil
}

func (s *authService) Introspect(ctx context.Context, req IntrospectRequest) (IntrospectResponse, error) {
	// Check if token is revoked
	revoked, err := s.revokedTokens.IsRevoked(ctx, req.Token)
	if err != nil {
		return IntrospectResponse{}, err
	}
	if revoked {
		return IntrospectResponse{Active: false}, nil
	}

	// Try to parse as JWT (access token)
	token, err := jwt.Parse(req.Token, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.signer.PublicKey(), nil
	})

	if err != nil || !token.Valid {
		// Not a valid access token, check if it's a refresh token
		stored, found, getErr := s.refreshTokenStore.Get(ctx, req.Token)
		if getErr == nil && found && time.Now().Before(stored.ExpiresAt) {
			return IntrospectResponse{
				Active:    true,
				Scope:     stored.Scope,
				ClientID:  stored.ClientID,
				TokenType: "refresh_token",
				Exp:       stored.ExpiresAt.Unix(),
				TenantID:  stored.TenantID,
			}, nil
		}
		return IntrospectResponse{Active: false}, nil
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return IntrospectResponse{Active: false}, nil
	}

	exp, _ := claims["exp"].(float64)
	iat, _ := claims["iat"].(float64)
	sub, _ := claims["sub"].(string)
	scope, _ := claims["scope"].(string)
	tenant, _ := claims["tenant"].(string)
	aud, _ := claims["aud"].(string)
	iss, _ := claims["iss"].(string)

	// Check for CAE (Critical Access Evaluation)
	// If the token is valid, we check if any revocation events occurred AFTER the token was issued (iat).
	// We convert iat to time.Time
	tokenIssuedAt := time.Unix(int64(iat), 0)

	// Query signal store
	if s.signalStore != nil {
		event, err := s.signalStore.GetLatestCriticalEvent(ctx, sub, tokenIssuedAt)
		if err == nil && event != nil {
			// A critical event happened after token issuance! Revoke access.
			return IntrospectResponse{
				Active: false,
				// We can't easily return custom reason fields in standard Introspect,
				// but 'active: false' is the enforcement.
			}, nil
		}
	}

	return IntrospectResponse{
		Active:    true,
		Scope:     scope,
		ClientID:  sub,
		TokenType: "access_token",
		Exp:       int64(exp),
		Iat:       int64(iat),
		Sub:       sub,
		Aud:       aud,
		Iss:       iss,
		TenantID:  tenant,
	}, nil
}

func (s *authService) Signal() SignalStore {
	return s.signalStore
}

func (s *authService) Revoke(ctx context.Context, req RevokeRequest) error {
	// Add token to revocation list
	if err := s.revokedTokens.Revoke(ctx, req.Token); err != nil {
		return err
	}

	// Also delete from refresh token store if it exists there
	_ = s.refreshTokenStore.Delete(ctx, req.Token)

	return nil
}

func (s *authService) SAML() *saml.Provider {
	return s.samlProvider
}

func (s *authService) Device() DeviceStore {
	return s.deviceStore
}

func (s *authService) TOTP() TOTPStore {
	return s.totpStore
}

// ErrInvalidCredentials is returned when login fails.
var ErrInvalidCredentials = &Error{"invalid_credentials", "invalid username or password"}

const (
	SystemTenantID  = "11111111-1111-1111-1111-111111111111"
	AnonymousUserID = "00000000-0000-0000-0000-000000000000"
)

var ErrMissingCodeChallenge = &Error{"invalid_request", "code_challenge is required"}
var ErrInvalidCodeChallengeMethod = &Error{"invalid_request", "only S256 code_challenge_method is supported"}
var ErrInvalidAuthorizationCode = &Error{"invalid_grant", "authorization code is invalid or expired"}
var ErrUnsupportedGrantType = &Error{"unsupported_grant_type", "only authorization_code grant is supported"}
var ErrInvalidCodeVerifier = &Error{"invalid_grant", "code_verifier does not match code_challenge"}
var ErrInvalidClient = &Error{"invalid_client", "client_id is not recognized"}
var ErrInvalidRedirectURI = &Error{"invalid_request", "redirect_uri is not registered for this client"}

// Error represents a service-specific error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return e.Message
}

func newInvalidScopeError(detail string) *Error {
	return &Error{"invalid_scope", detail}
}

type authorizationCode struct {
	Code                string
	ClientID            string
	RedirectURI         string
	Scope               string
	TenantID            string
	CodeChallenge       string
	CodeChallengeMethod string
	ExpiresAt           time.Time
}

type authorizationCodeStore struct {
	mu    sync.RWMutex
	codes map[string]authorizationCode
}

func newAuthorizationCodeStore() *authorizationCodeStore {
	return &authorizationCodeStore{codes: make(map[string]authorizationCode)}
}

func (s *authorizationCodeStore) Save(ctx context.Context, code authorizationCode) error {
	s.mu.Lock()
	s.codes[code.Code] = code
	s.mu.Unlock()
	return nil
}

func (s *authorizationCodeStore) Get(ctx context.Context, code string) (authorizationCode, bool, error) {
	s.mu.RLock()
	entry, ok := s.codes[code]
	s.mu.RUnlock()
	return entry, ok, nil
}

func (s *authorizationCodeStore) Delete(ctx context.Context, code string) error {
	s.mu.Lock()
	delete(s.codes, code)
	s.mu.Unlock()
	return nil
}

func generateAuthorizationCode() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func verifyCodeChallenge(challenge, method, verifier string) error {
	if method != "S256" {
		return ErrInvalidCodeChallengeMethod
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	if subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) != 1 {
		return ErrInvalidCodeVerifier
	}
	return nil
}

func buildAuthorizationRedirect(baseURI, code, state string) (string, error) {
	parsed, err := url.Parse(baseURI)
	if err != nil {
		return "", err
	}
	values := parsed.Query()
	values.Set("code", code)
	if state != "" {
		values.Set("state", state)
	}
	parsed.RawQuery = values.Encode()
	return parsed.String(), nil
}

func (s *authService) resolveClient(ctx context.Context, tenantID, clientID string) (ClientConfig, error) {
	if s.clientStore != nil {
		record, err := s.clientStore.GetClient(ctx, tenantID, clientID)
		if err != nil {
			if errors.Is(err, oauthclient.ErrNotFound) {
				return ClientConfig{}, ErrInvalidClient
			}
			return ClientConfig{}, err
		}
		cfg := clientConfigFromRecord(record)
		if err := cfg.validate(); err != nil {
			return ClientConfig{}, err
		}
		return cfg, nil
	}
	if s.clients == nil {
		return ClientConfig{}, ErrInvalidClient
	}
	client, ok := s.clients[clientKey{TenantID: tenantID, ClientID: clientID}]
	if !ok {
		return ClientConfig{}, ErrInvalidClient
	}
	return client, nil
}

func clientConfigFromRecord(record oauthclient.Client) ClientConfig {
	description := ""
	if record.Description.Valid {
		description = record.Description.String
	}
	clientType := record.ClientType
	if clientType == "" {
		clientType = "public"
	}
	return ClientConfig{
		ID:            record.ClientID,
		TenantID:      record.TenantID,
		Name:          record.Name,
		Description:   description,
		ClientType:    clientType,
		RedirectURIs:  append([]string(nil), record.RedirectURIs...),
		AllowedScopes: append([]string(nil), record.AllowedScopes...),
	}
}

// refreshTokenEntry represents a stored refresh token.
type refreshTokenEntry struct {
	Token       string
	ClientID    string
	TenantID    string
	Scope       string
	SubjectType string
	ExpiresAt   time.Time
}

// refreshTokenStore provides in-memory storage for refresh tokens.
type refreshTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]refreshTokenEntry
}

func newRefreshTokenStore() *refreshTokenStore {
	return &refreshTokenStore{tokens: make(map[string]refreshTokenEntry)}
}

func (s *refreshTokenStore) Save(ctx context.Context, entry refreshTokenEntry) error {
	s.mu.Lock()
	s.tokens[entry.Token] = entry
	s.mu.Unlock()
	return nil
}

func (s *refreshTokenStore) Get(ctx context.Context, token string) (refreshTokenEntry, bool, error) {
	s.mu.RLock()
	entry, ok := s.tokens[token]
	s.mu.RUnlock()
	return entry, ok, nil
}

func (s *refreshTokenStore) Delete(ctx context.Context, token string) error {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()
	return nil
}

// tokenRevocationStore provides in-memory storage for revoked tokens.
type tokenRevocationStore struct {
	mu      sync.RWMutex
	revoked map[string]time.Time
}

func newTokenRevocationStore() *tokenRevocationStore {
	return &tokenRevocationStore{revoked: make(map[string]time.Time)}
}

func (s *tokenRevocationStore) Revoke(ctx context.Context, token string) error {
	s.mu.Lock()
	s.revoked[token] = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *tokenRevocationStore) IsRevoked(ctx context.Context, token string) (bool, error) {
	s.mu.RLock()
	_, exists := s.revoked[token]
	s.mu.RUnlock()
	return exists, nil
}

// verifyClientSecret compares a plaintext secret against a bcrypt hash.
func verifyClientSecret(secret string, hash []byte) error {
	return bcrypt.CompareHashAndPassword(hash, []byte(secret))
}

func (s *authService) BeginWebAuthnRegistration(ctx context.Context, userID string) (*protocol.CredentialCreation, *webauthn.SessionData, error) {
	// 1. Fetch user (or create dummy adapter)
	// We need Name and DisplayName. For MVP, reusing ID as name or fetching from DirSvc is hard without token.
	// But usually registration happens when user is already logged in? Yes.
	// We can fetch from DirSvc? Or just use what we have.
	// Let's assume we fetch basic info or use placeholder if allow.
	user := &WebAuthnUser{
		ID:          userID,
		Name:        userID, // ideally email
		DisplayName: "User",
	}

	// 2. Load existing credentials to prevent re-registration
	creds, err := s.webAuthnStore.ListCredentials(ctx, userID)
	if err == nil {
		user.Credentials = creds
	}

	return s.webAuthn.BeginRegistration(user)
}

func (s *authService) FinishWebAuthnRegistration(ctx context.Context, userID string, session webauthn.SessionData, req *http.Request) error {
	user := &WebAuthnUser{
		ID: userID,
	}

	credential, err := s.webAuthn.FinishRegistration(user, session, req)
	if err != nil {
		return err
	}

	// Store credential
	// Using TenantID from context? registration usually requires auth, so yes.
	_, _ = middleware.TenantIDFromContext(ctx)
	tenantID := SystemTenantID // Fallback to System Tenant

	return s.webAuthnStore.SaveCredential(ctx, tenantID, userID, credential)
}

func (s *authService) BeginWebAuthnLogin(ctx context.Context, userID string) (*protocol.CredentialAssertion, *webauthn.SessionData, error) {
	// 1. Fetch user and credentials
	// Login might be "usernameless" (discoverable credentials) or username-first.
	// We are doing username-first for now implies we know userID.
	creds, err := s.webAuthnStore.ListCredentials(ctx, userID)
	if err != nil {
		return nil, nil, err
	}
	if len(creds) == 0 {
		return nil, nil, errors.New("no credentials found for user")
	}

	user := &WebAuthnUser{
		ID:          userID,
		Credentials: creds,
	}

	return s.webAuthn.BeginLogin(user)
}

func (s *authService) FinishWebAuthnLogin(ctx context.Context, userID string, session webauthn.SessionData, req *http.Request) (string, error) {
	// 1. Re-fetch user credential options
	creds, err := s.webAuthnStore.ListCredentials(ctx, userID)
	if err != nil {
		return "", err
	}
	user := &WebAuthnUser{
		ID:          userID,
		Credentials: creds,
	}

	credential, err := s.webAuthn.FinishLogin(user, session, req)
	if err != nil {
		return "", err
	}

	// 2. Update sign count
	if err := s.webAuthnStore.UpdateCredential(ctx, credential); err != nil {
		zap.L().Error("Failed to update credential sign count", zap.Error(err))
	}

	// 3. Issue Token (MFA success)
	// Retrieve TenantID from... context?
	// If this is a login flow, we might not have tenant yet if purely public endpoint?
	// But usually we do.
	_, _ = middleware.TenantIDFromContext(ctx)
	tenantID := SystemTenantID

	// Scopes? Default.
	return s.generateAccessToken(tenantID, userID, "openid", "user")
}

func (s *authService) WebAuthn() *webauthn.WebAuthn {
	return s.webAuthn
}
func (s *authService) SignUp(ctx context.Context, email, password, companyName, plan string) (string, string, error) {
	// 0. Check if Public Signup is allowed
	if s.deploymentMode != "saas" {
		return "", "", errors.New("public signup is disabled in this deployment mode")
	}

	// 1. Generate new Tenant ID
	tenantID := uuid.New().String()

	// 2. Create Tenant in Directory Service
	if plan == "" {
		plan = "free"
	}
	tenantPayload := map[string]interface{}{
		"id":   tenantID,
		"name": companyName,
		"plan": plan,
	}
	tenantBody, err := json.Marshal(tenantPayload)
	if err != nil {
		return "", "", err
	}
	reqTenant, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/tenants", s.directoryServiceURL), bytes.NewReader(tenantBody))
	if err != nil {
		return "", "", err
	}
	reqTenant.Header.Set("Content-Type", "application/json")
	if s.serviceAuthToken != "" {
		reqTenant.Header.Set(s.serviceAuthHeader, s.serviceAuthToken)
	}
	respTenant, err := s.httpClient.Do(reqTenant)
	if err != nil {
		return "", "", fmt.Errorf("failed to create tenant: %w", err)
	}
	defer respTenant.Body.Close()
	if respTenant.StatusCode != http.StatusCreated {
		return "", "", fmt.Errorf("directory service create tenant failed: status %d", respTenant.StatusCode)
	}

	// 3. Create User in Directory Service
	// We call POST /users directly on directory service URL, injecting the new Tenant ID header.
	// Payload must match CreateUserRequest: { "user": { ... } }
	userPayload := map[string]interface{}{
		"user": map[string]interface{}{
			"email":    email,
			"password": password,
			"status":   "active",
		},
	}
	body, err := json.Marshal(userPayload)
	if err != nil {
		return "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/users", s.directoryServiceURL), bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, tenantID)
	// Directory service /users is tenant-protected but might not require auth token if internal?
	// Based on api.go analysis, it only checks TenantID.
	// But it's safer to send service auth if configured/needed (though api.go didn't show it for /users).

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		// Try to read error body
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return "", "", fmt.Errorf("failed to create user: status %d, error: %s", resp.StatusCode, errResp.Error)
	}

	// 3. Login to get token
	// We call our own Login logic, but we need to pass the context with the new TenantID?
	// Login implementation derives TenantID from context using middleware.TenantIDFromContext.
	// We can't easily inject it into context for internal call without mocking middleware?
	// Actually, s.Login() reads context.
	// So we create a new context with tenantID.

	// Issue: middleware.TenantIDContextKey is unexported key type in middleware package.
	// We cannot set it from here using `context.WithValue` unless middleware exports the key or a setter.
	// Checking middleware/tenant.go... key IS unexported `type tenantContextKey string`.
	// BUT `TenantIDFromContext` reads it.
	// We can't inject it easily.

	// ALTERNATIVE: Use `s.privateKey` to mint token directly here without calling `Login`.
	// This is duplicate logic but cleaner than hacking context.

	// Read created user ID (response from POST /users includes it)
	var createUserResp struct {
		UserID string `json:"user_id"`
	}
	// We already decoded response? No.
	// Wait, I didn't decode success response above.
	// Need to re-read body if I didn't close it? `defer` closes at end of func.
	// Re-reading is fine if I decode it now.
	if err := json.NewDecoder(resp.Body).Decode(&createUserResp); err != nil {
		return "", "", fmt.Errorf("failed to decode create user response: %w", err)
	}

	claims := jwt.MapClaims{
		"sub":    createUserResp.UserID,
		"iss":    "identity-platform",
		"aud":    "client-app",
		"exp":    time.Now().Add(time.Hour * 1).Unix(),
		"iat":    time.Now().Unix(),
		"scope":  "openid profile email",
		"tenant": tenantID,
	}

	signedToken, err := s.signer.Sign(claims)
	if err != nil {
		return "", "", err
	}

	return signedToken, tenantID, nil
}

func (s *authService) GetSystemSetupStatus(ctx context.Context) (bool, error) {
	// Check if any users exist in the system tenant
	// We use the magic system tenant ID
	systemTenantID := "11111111-1111-1111-1111-111111111111"

	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/users", s.directoryServiceURL), nil)
	if err != nil {
		return false, err
	}

	q := req.URL.Query()
	q.Add("limit", "1")
	req.URL.RawQuery = q.Encode()

	req.Header.Set("Content-Type", "application/json")
	// Use system tenant ID to check THAT tenant
	req.Header.Set(middleware.DefaultTenantHeader, systemTenantID)
	if s.serviceAuthToken != "" {
		req.Header.Set(s.serviceAuthHeader, s.serviceAuthToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("directory service returned status %d", resp.StatusCode)
	}

	var listResp struct {
		Total int `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&listResp); err != nil {
		return false, err
	}

	// Setup is required if total users == 0
	return listResp.Total == 0, nil
}

func (s *authService) PerformSystemSetup(ctx context.Context, email, password string) (string, error) {
	// Double check that setup is allowed
	required, err := s.GetSystemSetupStatus(ctx)
	if err != nil {
		return "", err
	}
	if !required {
		return "", errors.New("system setup not required (or already completed)")
	}

	systemTenantID := "11111111-1111-1111-1111-111111111111"

	// Create the User in Directory Service
	userPayload := struct {
		User struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Status   string `json:"status"`
		} `json:"user"`
	}{
		User: struct {
			Email    string `json:"email"`
			Password string `json:"password"`
			Status   string `json:"status"`
		}{
			Email:    email,
			Password: password,
			Status:   "active",
		},
	}

	body, err := json.Marshal(userPayload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/users", s.directoryServiceURL), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, systemTenantID)
	if s.serviceAuthToken != "" {
		req.Header.Set(s.serviceAuthHeader, s.serviceAuthToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("failed to create system owner: %s", string(respBody))
	}

	var createResp struct {
		UserID string `json:"user_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		return "", err
	}

	// Sign a token for the new user
	claims := jwt.MapClaims{
		"sub":    createResp.UserID,
		"iss":    "identity-platform",
		"aud":    "admin-console",
		"exp":    time.Now().Add(time.Hour * 1).Unix(),
		"iat":    time.Now().Unix(),
		"scope":  "openid profile email",
		"tenant": systemTenantID,
		"role":   "owner",
	}

	return s.signer.Sign(claims)
}

func (s *authService) ListClients(ctx context.Context, tenantID string) ([]oauthclient.Client, error) {
	if s.clientStore == nil {
		return nil, errors.New("client store not configured")
	}
	return s.clientStore.ListClientsByTenant(ctx, tenantID)
}

func (s *authService) UpdateUserSelf(ctx context.Context, tenantID, userID string, updates map[string]interface{}) error {
	// Construct the payload for directory service
	type User struct {
		Password string `json:"password,omitempty"`
	}

	userPayload := User{}
	if pw, ok := updates["password"].(string); ok && pw != "" {
		userPayload.Password = pw
	}

	reqBody := struct {
		User User `json:"user"`
	}{
		User: userPayload,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/users/%s", s.directoryServiceURL, userID)
	req, err := http.NewRequestWithContext(ctx, "PUT", url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, tenantID)
	if s.serviceAuthToken != "" {
		req.Header.Set(s.serviceAuthHeader, s.serviceAuthToken)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("directory service update failed with status %d", resp.StatusCode)
	}

	return nil
}
