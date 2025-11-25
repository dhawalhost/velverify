package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/dhawalhost/velverify/internal/oauthclients"
	"github.com/dhawalhost/velverify/pkg/middleware"
	"github.com/golang-jwt/jwt/v5"
	"gopkg.in/square/go-jose.v2"
)

// Service defines the interface for the auth service.
type Service interface {
	Login(ctx context.Context, username, password string) (string, error)
	Authorize(ctx context.Context, req AuthorizeRequest) (AuthorizeResponse, error)
	Token(ctx context.Context, req TokenRequest) (TokenResponse, error)
	JWKS() jose.JSONWebKeySet
}

type authService struct {
	directoryServiceURL string
	httpClient          *http.Client
	privateKey          *rsa.PrivateKey
	serviceAuthHeader   string
	serviceAuthToken    string
	codeStore           *authorizationCodeStore
	clients             map[clientKey]ClientConfig
	clientStore         oauthclients.Store
}

// Config captures the settings for the auth service.
type Config struct {
	DirectoryServiceURL string
	ServiceAuthToken    string
	ServiceAuthHeader   string
	Clients             []ClientConfig
	ClientStore         oauthclients.Store
}

// NewService creates a new auth service.
func NewService(cfg Config) (Service, error) {
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

	return &authService{
		directoryServiceURL: cfg.DirectoryServiceURL,
		httpClient:          &http.Client{Timeout: 5 * time.Second},
		privateKey:          privateKey,
		serviceAuthHeader:   header,
		serviceAuthToken:    cfg.ServiceAuthToken,
		codeStore:           newAuthorizationCodeStore(),
		clients:             clientMap,
		clientStore:         cfg.ClientStore,
	}, nil
}

func (s *authService) Login(ctx context.Context, username, password string) (string, error) {
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
	defer resp.Body.Close()

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

	// 2. Generate a JWT.
	claims := jwt.MapClaims{
		"sub":    userResp.User.ID,
		"iss":    "identity-platform",
		"aud":    "client-app",
		"exp":    time.Now().Add(time.Hour * 1).Unix(),
		"iat":    time.Now().Unix(),
		"scope":  "openid profile email",
		"tenant": tenantID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "dummy-key-id"

	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// JWKS returns the JSON Web Key Set.
func (s *authService) JWKS() jose.JSONWebKeySet {
	return jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{
			{
				Key:       &s.privateKey.PublicKey,
				KeyID:     "dummy-key-id",
				Algorithm: "RS256",
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
	s.codeStore.Save(entry)
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
	if req.GrantType != "authorization_code" {
		return TokenResponse{}, ErrUnsupportedGrantType
	}
	client, err := s.resolveClient(ctx, tenantID, req.ClientID)
	if err != nil {
		return TokenResponse{}, err
	}
	if !client.allowsRedirect(req.RedirectURI) {
		return TokenResponse{}, ErrInvalidRedirectURI
	}
	code, found := s.codeStore.Get(req.Code)
	if !found || time.Now().After(code.ExpiresAt) {
		return TokenResponse{}, ErrInvalidAuthorizationCode
	}
	if code.ClientID != req.ClientID || code.RedirectURI != req.RedirectURI || code.TenantID != tenantID {
		return TokenResponse{}, ErrInvalidAuthorizationCode
	}
	if err := verifyCodeChallenge(code.CodeChallenge, code.CodeChallengeMethod, req.CodeVerifier); err != nil {
		return TokenResponse{}, err
	}
	s.codeStore.Delete(req.Code)

	// Generate a JWT.
	claims := jwt.MapClaims{
		"sub":    code.ClientID,
		"iss":    "identity-platform",
		"aud":    "client-app",
		"exp":    time.Now().Add(time.Hour * 1).Unix(),
		"iat":    time.Now().Unix(),
		"scope":  code.Scope,
		"tenant": tenantID,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = "dummy-key-id"

	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return TokenResponse{}, err
	}

	return TokenResponse{
		AccessToken: signedToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	}, nil
}

// ErrInvalidCredentials is returned when login fails.
var ErrInvalidCredentials = &Error{"invalid_credentials", "invalid username or password"}
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

func (s *authorizationCodeStore) Save(code authorizationCode) {
	s.mu.Lock()
	s.codes[code.Code] = code
	s.mu.Unlock()
}

func (s *authorizationCodeStore) Get(code string) (authorizationCode, bool) {
	s.mu.RLock()
	entry, ok := s.codes[code]
	s.mu.RUnlock()
	return entry, ok
}

func (s *authorizationCodeStore) Delete(code string) {
	s.mu.Lock()
	delete(s.codes, code)
	s.mu.Unlock()
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
			if errors.Is(err, oauthclients.ErrNotFound) {
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

func clientConfigFromRecord(record oauthclients.Client) ClientConfig {
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
