package auth

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
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
}

// NewService creates a new auth service.
func NewService(directoryServiceURL string) (Service, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}

	return &authService{
		directoryServiceURL: directoryServiceURL,
		httpClient:          &http.Client{Timeout: 5 * time.Second},
		privateKey:          privateKey,
	}, nil
}

func (s *authService) Login(ctx context.Context, username, password string) (string, error) {
	// 1. Call the directory service to get the user by email.
	req, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s/users?email=%s", s.directoryServiceURL, username), nil)
	if err != nil {
		return "", err
	}
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", ErrInvalidCredentials
	}

	var userResp struct {
		User struct {
			ID       string `json:"id"`
			Email    string `json:"email"`
			Password string `json:"password"`
		} `json:"user"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userResp); err != nil {
		return "", err
	}

	// 2. Compare the provided password with the stored hash.
	if err := bcrypt.CompareHashAndPassword([]byte(userResp.User.Password), []byte(password)); err != nil {
		return "", ErrInvalidCredentials
	}

	// 3. Generate a JWT.
	claims := jwt.MapClaims{
		"sub":   userResp.User.ID,
		"iss":   "identity-platform",
		"aud":   "client-app",
		"exp":   time.Now().Add(time.Hour * 1).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "openid profile email",
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
	// In a real implementation, we would:
	// 1. Validate the client_id.
	// 2. Validate the redirect_uri.
	// 3. Store the authorization request details.
	// 4. Redirect the user to the login page.
	// For now, we'll just redirect to a dummy login page with the request parameters.
	redirectURI := fmt.Sprintf("/login?response_type=%s&client_id=%s&redirect_uri=%s&scope=%s&state=%s",
		req.ResponseType, req.ClientID, req.RedirectURI, req.Scope, req.State)
	return AuthorizeResponse{RedirectURI: redirectURI}, nil
}

func (s *authService) Token(ctx context.Context, req TokenRequest) (TokenResponse, error) {
	// In a real implementation, we would:
	// 1. Validate the client_id.
	// 2. Validate the authorization code.
	// 3. Exchange the code for a token.
	// For now, we'll just return a dummy token.

	// 3. Generate a JWT.
	claims := jwt.MapClaims{
		"sub":   "dummy-user-id",
		"iss":   "identity-platform",
		"aud":   "client-app",
		"exp":   time.Now().Add(time.Hour * 1).Unix(),
		"iat":   time.Now().Unix(),
		"scope": "openid profile email",
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

// Error represents a service-specific error.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *Error) Error() string {
	return e.Message
}
