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
	"github.com/dhawalhost/wardseal/internal/rbac"
	"github.com/dhawalhost/wardseal/internal/saml"
	"github.com/dhawalhost/wardseal/pkg/kms"
	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/golang-jwt/jwt/v5"
	"github.com/pquerna/otp/totp"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/go-jose/go-jose.v2"
)

// Service defines the interface for the auth service.
type Service interface {
	Login(ctx context.Context, username, password, deviceID, userAgent, ip, clientOSVersion string) (string, error)
	Authorize(ctx context.Context, userID string, req AuthorizeRequest) (AuthorizeResponse, error)
	Token(ctx context.Context, req TokenRequest) (TokenResponse, error)
	Introspect(ctx context.Context, req IntrospectRequest) (IntrospectResponse, error)
	Revoke(ctx context.Context, req RevokeRequest) error
	SAML() *saml.Provider
	JWKS() jose.JSONWebKeySet
	Device() DeviceRepository
	Signal() SignalRepository
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
	GetOIDCConfiguration() OpenIDConfiguration
	LoginWithMFAStepUp(ctx context.Context, stepUpToken, totpCode string) (string, error)

	// Client Management for Portal
	ListClients(ctx context.Context, tenantID string) ([]oauthclient.Client, error)

	// User Self-Update
	UpdateUserSelf(ctx context.Context, tenantID, userID string, updates map[string]interface{}) error

	// TOTP MFA
	TOTP() TOTPRepository

	// User Lookup
	LookupUser(ctx context.Context, tenantID, email string) (LookupResult, error)
	// SignUp
	SignUp(ctx context.Context, email, password, companyName, plan string) (string, string, string, error)

	// System Setup
	GetSystemSetupStatus(ctx context.Context) (bool, error)
	PerformSystemSetup(ctx context.Context, email, password string) (string, error)

	ResolveTenantSlug(ctx context.Context, slug string) (string, error)
	UIURL() string
	ValidateToken(tokenString string) (*middleware.Claims, error)
}

type LookupResult struct {
	UserID          string `json:"user_id"`
	WebAuthnEnabled bool   `json:"webauthn_enabled"`
	TenantID        string `json:"tenant_id,omitempty"`
	TenantSlug      string `json:"tenant_slug,omitempty"`
}

type authService struct {
	directoryServiceURL string
	httpClient          *http.Client
	signer              kms.Signer
	serviceAuthHeader   string
	serviceAuthToken    string
	codeStore           AuthorizationCodeRepository
	refreshTokenStore   RefreshTokenRepository
	revokedTokens       RevocationRepository
	clients             map[clientKey]ClientConfig
	clientStore         oauthclient.Repository
	samlProvider        *saml.Provider
	deviceStore         DeviceRepository
	signalStore         SignalRepository
	riskEngine          *RiskEngine
	webAuthn            *webauthn.WebAuthn
	webAuthnStore       WebAuthnRepository
	brandingStore       BrandingRepository
	federationStore     FederationRepository
	totpStore           TOTPRepository
	ssoProviderStore    SSOProviderRepository
	tenantStore         TenantRepository
	appStore            DeveloperAppRepository
	rbacStore           rbac.Repository
	ipPolicyStore       IPPolicyRepository
	deploymentMode      string
	baseURL             string
	uiURL               string
}

// AuthorizationCodeRepository defines the interface for storing authorization codes.
type AuthorizationCodeRepository interface {
	Save(ctx context.Context, code authorizationCode) error
	Get(ctx context.Context, code string) (authorizationCode, bool, error)
	Delete(ctx context.Context, code string) error
}

// RefreshTokenRepository defines the interface for storing refresh tokens.
type RefreshTokenRepository interface {
	Save(ctx context.Context, entry refreshTokenEntry) error
	Get(ctx context.Context, token string) (refreshTokenEntry, bool, error)
	Delete(ctx context.Context, token string) error
}

// RevocationRepository defines the interface for token revocation.
type RevocationRepository interface {
	Revoke(ctx context.Context, token string) error
	IsRevoked(ctx context.Context, token string) (bool, error)
}

// Config captures the settings for the auth service.
type Config struct {
	DirectoryServiceURL string
	ServiceAuthToken    string
	ServiceAuthHeader   string
	Clients             []ClientConfig
	ClientStore         oauthclient.Repository
	SAMLStore           *saml.Store
	DeviceStore         DeviceRepository
	SignalStore         SignalRepository
	WebAuthnStore       WebAuthnRepository
	BrandingStore       BrandingRepository
	FederationStore     FederationRepository
	BaseURL             string
	// Persistent stores (optional, defaults to in-memory if not provided)
	CodeStore        AuthorizationCodeRepository
	RefreshStore     RefreshTokenRepository
	RevocationStore  RevocationRepository
	TOTPStore        TOTPRepository
	SSOProviderStore SSOProviderRepository
	TenantStore      TenantRepository
	AppStore         DeveloperAppRepository
	IPPolicyStore    IPPolicyRepository
	RBACStore        rbac.Repository
	UIURL            string
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

	rpID := "localhost"
	if parsedBaseURL, parseErr := url.Parse(cfg.BaseURL); parseErr == nil {
		if host := parsedBaseURL.Hostname(); host != "" {
			rpID = host
		}
	}

	// WebAuthn Init
	w, err := webauthn.New(&webauthn.Config{
		RPDisplayName: "WardSeal Identity",
		RPID:          rpID,
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
	var codeStore AuthorizationCodeRepository = newAuthorizationCodeRepository()
	if cfg.CodeStore != nil {
		codeStore = cfg.CodeStore
	}
	var refreshStore RefreshTokenRepository = newRefreshTokenRepository()
	if cfg.RefreshStore != nil {
		refreshStore = cfg.RefreshStore
	}
	var revocationStore RevocationRepository = newTokenRevocationRepository()
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
		riskEngine:          NewRiskEngine(cfg.DeviceStore, cfg.SignalStore, zap.L()).WithIPPolicy(cfg.IPPolicyStore, nil),
		webAuthn:            w,
		webAuthnStore:       cfg.WebAuthnStore,
		federationStore:     cfg.FederationStore,
		brandingStore:       cfg.BrandingStore,
		ssoProviderStore:    cfg.SSOProviderStore,
		tenantStore:         cfg.TenantStore,
		appStore:            cfg.AppStore,
		rbacStore:           cfg.RBACStore,
		ipPolicyStore:       cfg.IPPolicyStore,
		deploymentMode:      deploymentMode,
		baseURL:             cfg.BaseURL,
		uiURL:               cfg.UIURL,
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
		zap.L().Error("Risk evaluation failed", zap.Error(err))
	} else {
		if risk.Level == RiskLevelHigh {
			zap.L().Warn("Login blocked due to high risk",
				zap.String("user_id", userResp.User.ID),
				zap.Int("score", risk.Score),
				zap.Strings("factors", risk.Factors))
			return "", &Error{"access_denied", "login blocked due to security risk"}
		}
		if risk.Level == RiskLevelMedium {
			zap.L().Info("MFA step-up required due to medium risk",
				zap.String("user_id", userResp.User.ID),
				zap.Int("score", risk.Score),
				zap.Strings("factors", risk.Factors))
			// Generate a short-lived step-up token
			stepUpToken, err := s.generateStepUpToken(tenantID, userResp.User.ID)
			if err != nil {
				return "", err
			}
			return stepUpToken, ErrMFARequired
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

	// Add RBAC claims
	if s.rbacStore != nil {
		roles, err := s.rbacStore.GetUserRoles(ctx, tenantID, userResp.User.ID)
		if err == nil {
			roleNames := make([]string, len(roles))
			for i, r := range roles {
				roleNames[i] = r.Name
			}
			claims["roles"] = roleNames
		}
		perms, err := s.rbacStore.GetUserPermissions(ctx, tenantID, userResp.User.ID)
		if err == nil {
			permList := make([]string, len(perms))
			for i, p := range perms {
				permList[i] = fmt.Sprintf("%s:%s", p.Resource, p.Action)
			}
			claims["permissions"] = permList
		}
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

func slugifyTenantName(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	re := regexp.MustCompile(`[^a-z0-9]+`)
	slug := re.ReplaceAllString(name, "-")
	slug = strings.Trim(slug, "-")
	if slug == "" {
		slug = "tenant"
	}
	if len(slug) > 48 {
		slug = strings.Trim(slug[:48], "-")
		if slug == "" {
			slug = "tenant"
		}
	}
	return slug
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
		TenantID:        tenantID,
		TenantSlug: func() string {
			if s.tenantStore == nil {
				return ""
			}
			slug, err := s.tenantStore.GetSlugByID(ctx, tenantID)
			if err != nil {
				zap.L().Warn("Failed to resolve tenant slug", zap.String("tenant_id", tenantID), zap.Error(err))
				return ""
			}
			return slug
		}(),
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

func (s *authService) GetOIDCConfiguration() OpenIDConfiguration {
	return OpenIDConfiguration{
		Issuer:                            s.baseURL,
		AuthorizationEndpoint:             fmt.Sprintf("%s/oauth2/authorize", s.baseURL),
		TokenEndpoint:                     fmt.Sprintf("%s/oauth2/token", s.baseURL),
		UserinfoEndpoint:                  fmt.Sprintf("%s/api/v1/user/profile", s.baseURL),
		JwksURI:                           fmt.Sprintf("%s/.well-known/jwks.json", s.baseURL),
		ScopesSupported:                   []string{"openid", "profile", "email", "offline_access"},
		ResponseTypesSupported:            []string{"code"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token", "client_credentials"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post"},
		CodeChallengeMethodsSupported:     []string{"S256"},
		ClaimsSupported:                   []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "tenant"},
	}
}

func (s *authService) ResolveTenantSlug(ctx context.Context, slug string) (string, error) {
	if s.tenantStore == nil {
		return "", errors.New("tenant store not configured")
	}
	return s.tenantStore.GetIDBySlug(ctx, slug)
}

func (s *authService) Authorize(ctx context.Context, userID string, req AuthorizeRequest) (AuthorizeResponse, error) {
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
		UserID:              userID,
		Nonce:               req.Nonce,
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
	if !client.allowsGrant("authorization_code") {
		return TokenResponse{}, &Error{"unauthorized_client", "authorization_code grant is not enabled for this client"}
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

	return s.issueTokens(ctx, tenantID, req.ClientID, code.Scope, code.UserID, code.Nonce)
}

func (s *authService) handleClientCredentialsGrant(ctx context.Context, tenantID string, req TokenRequest) (TokenResponse, error) {
	if req.ClientID == "" {
		return TokenResponse{}, &Error{"invalid_request", "client_id is required"}
	}

	client, err := s.resolveClient(ctx, tenantID, req.ClientID)
	if err != nil {
		return TokenResponse{}, err
	}
	if !client.allowsGrant("client_credentials") {
		return TokenResponse{}, &Error{"unauthorized_client", "client_credentials grant is not enabled for this client"}
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
	accessToken, err := s.generateAccessToken(ctx, tenantID, req.ClientID, scope, "")
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

	client, err := s.resolveClient(ctx, tenantID, stored.ClientID)
	if err != nil {
		return TokenResponse{}, err
	}
	if !client.allowsGrant("refresh_token") {
		return TokenResponse{}, &Error{"unauthorized_client", "refresh_token grant is not enabled for this client"}
	}

	// Rotate refresh token - delete old and issue new
	_ = s.refreshTokenStore.Delete(ctx, req.RefreshToken)

	return s.issueTokens(ctx, tenantID, stored.ClientID, stored.Scope, stored.SubjectType, "")
}

func (s *authService) issueTokens(ctx context.Context, tenantID, clientID, scope, userID, nonce string) (TokenResponse, error) {
	accessToken, err := s.generateAccessToken(ctx, tenantID, clientID, scope, userID)
	if err != nil {
		return TokenResponse{}, err
	}

	refreshToken, err := s.generateRefreshToken(ctx, tenantID, clientID, scope, userID)
	if err != nil {
		return TokenResponse{}, err
	}

	resp := TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
		RefreshToken: refreshToken,
		Scope:        scope,
	}

	if hasScope(scope, "openid") {
		idToken, err := s.generateIDToken(ctx, tenantID, clientID, userID, nonce)
		if err != nil {
			return TokenResponse{}, err
		}
		resp.IDToken = idToken
	}

	return resp, nil
}

func (s *authService) issueTokensWithoutRefresh(ctx context.Context, tenantID, clientID, scope, userID, nonce string) (TokenResponse, error) {
	accessToken, err := s.generateAccessToken(ctx, tenantID, clientID, scope, userID)
	if err != nil {
		return TokenResponse{}, err
	}

	resp := TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
		Scope:       scope,
	}

	if hasScope(scope, "openid") {
		idToken, err := s.generateIDToken(ctx, tenantID, clientID, userID, nonce)
		if err != nil {
			return TokenResponse{}, err
		}
		resp.IDToken = idToken
	}

	return resp, nil
}

func (s *authService) generateAccessToken(ctx context.Context, tenantID, clientID, scope, userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub":    clientID,
		"iss":    "identity-platform",
		"aud":    "client-app",
		"exp":    time.Now().Add(time.Hour * 1).Unix(),
		"iat":    time.Now().Unix(),
		"scope":  scope,
		"tenant": tenantID,
	}
	if userID != "" {
		claims["user_id"] = userID
		// Add RBAC claims
		if s.rbacStore != nil {
			roles, err := s.rbacStore.GetUserRoles(ctx, tenantID, userID)
			if err == nil {
				roleNames := make([]string, len(roles))
				for i, r := range roles {
					roleNames[i] = r.Name
				}
				claims["roles"] = roleNames
			}
		}
	}

	return s.signer.Sign(claims)
}

func (s *authService) generateIDToken(ctx context.Context, tenantID, clientID, userID, nonce string) (string, error) {
	subject := userID
	if subject == "" {
		subject = clientID
	}

	claims := jwt.MapClaims{
		"sub":    subject,
		"iss":    fmt.Sprintf("%s/t/%s", s.baseURL, tenantID),
		"aud":    clientID,
		"exp":    time.Now().Add(time.Hour).Unix(),
		"iat":    time.Now().Unix(),
		"tenant": tenantID,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Add RBAC claims for OIDC
	if userID != "" && s.rbacStore != nil {
		roles, err := s.rbacStore.GetUserRoles(ctx, tenantID, userID)
		if err == nil {
			roleNames := make([]string, len(roles))
			for i, r := range roles {
				roleNames[i] = r.Name
			}
			claims["roles"] = roleNames
		}

		// Permissions in ID token if profile scope is requested
		// Note: nonce check is usually for OIDC flows where scopes were already validated
		perms, err := s.rbacStore.GetUserPermissions(ctx, tenantID, userID)
		if err == nil {
			permList := make([]string, len(perms))
			for i, p := range perms {
				permList[i] = fmt.Sprintf("%s:%s", p.Resource, p.Action)
			}
			claims["permissions"] = permList
		}
	}

	return s.signer.Sign(claims)
}

func hasScope(scope, target string) bool {
	for _, value := range strings.Fields(scope) {
		if value == target {
			return true
		}
	}
	return false
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

func (s *authService) Signal() SignalRepository {
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

func (s *authService) Device() DeviceRepository {
	return s.deviceStore
}

func (s *authService) TOTP() TOTPRepository {
	return s.totpStore
}

// ErrMFARequired is returned when login requires a second factor.
var ErrMFARequired = &Error{"mfa_required", "additional authentication required"}

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
	Code                string    `db:"code"`
	ClientID            string    `db:"client_id"`
	RedirectURI         string    `db:"redirect_uri"`
	Scope               string    `db:"scope"`
	TenantID            string    `db:"tenant_id"`
	UserID              string    `db:"user_id"`
	Nonce               string    `db:"nonce"`
	CodeChallenge       string    `db:"code_challenge"`
	CodeChallengeMethod string    `db:"code_challenge_method"`
	ExpiresAt           time.Time `db:"expires_at"`
}

type authorizationCodeRepository struct {
	mu    sync.RWMutex
	codes map[string]authorizationCode
}

func newAuthorizationCodeRepository() *authorizationCodeRepository {
	return &authorizationCodeRepository{codes: make(map[string]authorizationCode)}
}

func (s *authorizationCodeRepository) Save(ctx context.Context, code authorizationCode) error {
	s.mu.Lock()
	s.codes[code.Code] = code
	s.mu.Unlock()
	return nil
}

func (s *authorizationCodeRepository) Get(ctx context.Context, code string) (authorizationCode, bool, error) {
	s.mu.RLock()
	entry, ok := s.codes[code]
	s.mu.RUnlock()
	return entry, ok, nil
}

func (s *authorizationCodeRepository) Delete(ctx context.Context, code string) error {
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

func (s *authService) UIURL() string {
	return s.uiURL
}

func (s *authService) resolveClient(ctx context.Context, tenantID, clientID string) (ClientConfig, error) {
	if s.clientStore != nil {
		record, err := s.clientStore.GetClient(ctx, tenantID, clientID)
		if err == nil {
			cfg := clientConfigFromRecord(record)
			if err := cfg.validate(); err == nil {
				return cfg, nil
			}
		}
	}

	// Fallback to Developer Portal apps
	if s.appStore != nil {
		app, err := s.appStore.GetByClientID(ctx, clientID)
		if err == nil && app != nil {
			// Ensure tenant mismatch is caught if needed, though for public/developer apps
			// we might allow it depending on policy.
			// But usually we want to enforce it.
			if app.TenantID != tenantID {
				return ClientConfig{}, ErrInvalidClient
			}

			var redirectURIs []string
			_ = json.Unmarshal(app.RedirectURIs, &redirectURIs)

			var allowedScopes []string
			_ = json.Unmarshal(app.Scopes, &allowedScopes)

			var grantTypes []string
			_ = json.Unmarshal(app.GrantTypes, &grantTypes)

			return ClientConfig{
				ID:            app.ClientID,
				TenantID:      app.TenantID,
				Name:          app.Name,
				ClientType:    app.AppType,
				RedirectURIs:  redirectURIs,
				AllowedScopes: allowedScopes,
				GrantTypes:    grantTypes,
			}.withDefaults(), nil
		}
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
	}.withDefaults()
}

// refreshTokenEntry represents a stored refresh token.
type refreshTokenEntry struct {
	Token       string    `db:"token"`
	ClientID    string    `db:"client_id"`
	TenantID    string    `db:"tenant_id"`
	Scope       string    `db:"scope"`
	SubjectType string    `db:"subject_type"`
	ExpiresAt   time.Time `db:"expires_at"`
}

// refreshTokenRepository provides in-memory storage for refresh tokens.
type refreshTokenRepository struct {
	mu     sync.RWMutex
	tokens map[string]refreshTokenEntry
}

func newRefreshTokenRepository() *refreshTokenRepository {
	return &refreshTokenRepository{tokens: make(map[string]refreshTokenEntry)}
}

func (s *refreshTokenRepository) Save(ctx context.Context, entry refreshTokenEntry) error {
	s.mu.Lock()
	s.tokens[entry.Token] = entry
	s.mu.Unlock()
	return nil
}

func (s *refreshTokenRepository) Get(ctx context.Context, token string) (refreshTokenEntry, bool, error) {
	s.mu.RLock()
	entry, ok := s.tokens[token]
	s.mu.RUnlock()
	return entry, ok, nil
}

func (s *refreshTokenRepository) Delete(ctx context.Context, token string) error {
	s.mu.Lock()
	delete(s.tokens, token)
	s.mu.Unlock()
	return nil
}

// tokenRevocationRepository provides in-memory storage for revoked tokens.
type tokenRevocationRepository struct {
	mu      sync.RWMutex
	revoked map[string]time.Time
}

func newTokenRevocationRepository() *tokenRevocationRepository {
	return &tokenRevocationRepository{revoked: make(map[string]time.Time)}
}

func (s *tokenRevocationRepository) Revoke(ctx context.Context, token string) error {
	s.mu.Lock()
	s.revoked[token] = time.Now()
	s.mu.Unlock()
	return nil
}

func (s *tokenRevocationRepository) IsRevoked(ctx context.Context, token string) (bool, error) {
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
	tenantID, _ := middleware.TenantIDFromContext(ctx)
	if tenantID == "" {
		tenantID = SystemTenantID
	}

	// Scopes? Default.
	return s.generateAccessToken(ctx, tenantID, "", "openid", userID)
}

func (s *authService) WebAuthn() *webauthn.WebAuthn {
	return s.webAuthn
}
func (s *authService) SignUp(ctx context.Context, email, password, companyName, plan string) (string, string, string, error) {
	// 0. Check if Public Signup is allowed
	if s.deploymentMode != "saas" {
		return "", "", "", errors.New("public signup is disabled in this deployment mode")
	}

	// 0.1 Check if email already exists globally
	respDisc, err := s.httpClient.Get(fmt.Sprintf("%s/internal/discover?email=%s", s.directoryServiceURL, url.QueryEscape(email)))
	if err == nil {
		defer respDisc.Body.Close()
		if respDisc.StatusCode == http.StatusOK {
			return "", "", "", errors.New("an account with this email already exists; please log in to your existing organization")
		}
	}

	// 1. Generate & Create Tenant in Directory Service (with retry for collisions)
	var tenantID string
	baseSlug := slugifyTenantName(companyName)
	tenantSlug := baseSlug
	maxRetries := 5
	for i := 0; i < maxRetries; i++ {
		tenantID = generateShortID()
		if i == 0 {
			tenantSlug = baseSlug
		} else {
			suffix := tenantID
			if len(suffix) > 6 {
				suffix = suffix[:6]
			}
			tenantSlug = fmt.Sprintf("%s-%s", baseSlug, suffix)
		}

		tenantPayload := map[string]interface{}{
			"id":   tenantID,
			"name": companyName,
			"slug": tenantSlug,
			"plan": plan,
		}
		tenantBody, err := json.Marshal(tenantPayload)
		if err != nil {
			return "", "", "", err
		}

		reqTenant, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/tenants", s.directoryServiceURL), bytes.NewReader(tenantBody))
		if err != nil {
			return "", "", "", err
		}
		reqTenant.Header.Set("Content-Type", "application/json")
		if s.serviceAuthToken != "" {
			reqTenant.Header.Set(s.serviceAuthHeader, s.serviceAuthToken)
		}

		respTenant, err := s.httpClient.Do(reqTenant)
		if err != nil {
			return "", "", "", fmt.Errorf("failed to create tenant: %w", err)
		}
		defer respTenant.Body.Close()

		if respTenant.StatusCode == http.StatusCreated {
			goto TenantCreated
		}

		if respTenant.StatusCode == http.StatusConflict && i < maxRetries-1 {
			// Collision! Retry with a new ID
			continue
		}

		return "", "", "", fmt.Errorf("directory service create tenant failed: status %d", respTenant.StatusCode)
	}

TenantCreated:

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
		return "", "", "", err
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/users", s.directoryServiceURL), bytes.NewReader(body))
	if err != nil {
		return "", "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(middleware.DefaultTenantHeader, tenantID)
	// Directory service /users is tenant-protected but might not require auth token if internal?
	// Based on api.go analysis, it only checks TenantID.
	// But it's safer to send service auth if configured/needed (though api.go didn't show it for /users).

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", "", "", err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusCreated {
		// Try to read error body
		var errResp struct {
			Error string `json:"error"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&errResp)
		return "", "", "", fmt.Errorf("failed to create user: status %d, error: %s", resp.StatusCode, errResp.Error)
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
		return "", "", "", fmt.Errorf("failed to decode create user response: %w", err)
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
		return "", "", "", err
	}

	return signedToken, tenantID, tenantSlug, nil
}

func (s *authService) GetSystemSetupStatus(ctx context.Context) (bool, error) {
	// Check if any users exist in the system tenant
	// Resolve canonical system tenant slug to tenant ID when available; fallback to literal system tenant ID
	systemTenantID, err := s.ResolveTenantSlug(ctx, "admin")
	if err != nil {
		return false, fmt.Errorf("failed to resolve system tenant: %w", err)
	}
	if systemTenantID == "" {
		systemTenantID = "admin-system"
	}

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

	systemTenantID, err := s.ResolveTenantSlug(ctx, "admin")
	if err != nil {
		return "", fmt.Errorf("failed to resolve system tenant: %w", err)
	}
	if systemTenantID == "" {
		systemTenantID = "admin-system"
	}

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

func generateShortID() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 10)
	_, _ = rand.Read(b)
	result := make([]byte, len(b))
	for i := range b {
		result[i] = charset[int(b[i])%len(charset)]
	}
	return "ws-" + string(result)
}

func (s *authService) generatePasswordSetupToken(tenantID, userID, mode string, expiresHours int) (string, time.Time, error) {
	if tenantID == "" || userID == "" {
		return "", time.Time{}, fmt.Errorf("tenant and user are required")
	}
	if mode != "invite" && mode != "reset" {
		return "", time.Time{}, fmt.Errorf("invalid mode")
	}
	if expiresHours <= 0 {
		expiresHours = 72
	}
	if expiresHours > 168 {
		expiresHours = 168
	}

	now := time.Now()
	expiresAt := now.Add(time.Duration(expiresHours) * time.Hour)
	claims := jwt.MapClaims{
		"iss":     s.baseURL,
		"aud":     "wardseal-password-setup",
		"sub":     userID,
		"tenant":  tenantID,
		"purpose": "password_setup",
		"mode":    mode,
		"iat":     now.Unix(),
		"exp":     expiresAt.Unix(),
		"nbf":     now.Unix(),
	}

	token, err := s.signer.Sign(claims)
	if err != nil {
		return "", time.Time{}, err
	}

	return token, expiresAt, nil
}

func (s *authService) setPasswordWithSetupToken(ctx context.Context, tokenString, password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters")
	}

	revoked, err := s.revokedTokens.IsRevoked(ctx, tokenString)
	if err != nil {
		return fmt.Errorf("failed to validate setup token")
	}
	if revoked {
		return fmt.Errorf("setup token already used or revoked")
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != s.signer.Algorithm() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.signer.PublicKey(), nil
	})
	if err != nil {
		return fmt.Errorf("invalid setup token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || !token.Valid {
		return fmt.Errorf("invalid setup token")
	}

	purpose, _ := claims["purpose"].(string)
	if purpose != "password_setup" {
		return fmt.Errorf("invalid setup token purpose")
	}

	tenantID, _ := claims["tenant"].(string)
	userID, _ := claims["sub"].(string)
	if tenantID == "" || userID == "" {
		return fmt.Errorf("invalid setup token claims")
	}

	if err := s.UpdateUserSelf(ctx, tenantID, userID, map[string]interface{}{"password": password}); err != nil {
		return err
	}

	if err := s.revokedTokens.Revoke(ctx, tokenString); err != nil {
		return fmt.Errorf("password updated but failed to revoke setup token")
	}

	return nil
}

func (s *authService) ValidateToken(tokenString string) (*middleware.Claims, error) {
	// If the signer is a LocalSigner or VaultSigner, we can use its PublicKey to verify
	// But the signer interface doesn't have a generic verify yet in a way that returns Claims.
	// However, we can use jwt.ParseWithClaims with the public key.

	token, err := jwt.ParseWithClaims(tokenString, &middleware.Claims{}, func(token *jwt.Token) (interface{}, error) {
		// Verify the algorithm matches
		if token.Method.Alg() != s.signer.Algorithm() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.signer.PublicKey(), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*middleware.Claims); ok && token.Valid {
		return claims, nil
	}

	return nil, fmt.Errorf("invalid token")
}

func (s *authService) generateStepUpToken(tenantID, userID string) (string, error) {
	claims := jwt.MapClaims{
		"sub":     userID,
		"iss":     s.baseURL,
		"aud":     "wardseal-mfa-stepup",
		"tenant":  tenantID,
		"purpose": "mfa_stepup",
		"iat":     time.Now().Unix(),
		"exp":     time.Now().Add(5 * time.Minute).Unix(),
	}
	return s.signer.Sign(claims)
}

func (s *authService) LoginWithMFAStepUp(ctx context.Context, stepUpToken, totpCode string) (string, error) {
	token, err := jwt.Parse(stepUpToken, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != s.signer.Algorithm() {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.signer.PublicKey(), nil
	})
	if err != nil || !token.Valid {
		return "", fmt.Errorf("invalid step-up token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return "", fmt.Errorf("invalid token claims")
	}

	if purpose, _ := claims["purpose"].(string); purpose != "mfa_stepup" {
		return "", fmt.Errorf("invalid token purpose")
	}

	userID, _ := claims["sub"].(string)
	tenantID, _ := claims["tenant"].(string)

	if userID == "" || tenantID == "" {
		return "", fmt.Errorf("missing user or tenant in token")
	}

	// Verify TOTP
	if s.totpStore == nil {
		return "", fmt.Errorf("TOTP store not configured")
	}
	secret, err := s.totpStore.GetByIdentity(ctx, tenantID, userID)
	if err != nil || secret == nil {
		return "", fmt.Errorf("TOTP not enrolled")
	}

	if !totp.Validate(totpCode, secret.Secret) {
		return "", fmt.Errorf("invalid TOTP code")
	}

	return s.generateAccessToken(ctx, tenantID, "", "openid profile email", userID)
}
