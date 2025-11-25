package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/dhawalhost/velverify/pkg/middleware"
	"github.com/gin-gonic/gin"
)

func TestAuthorizationCodePkceFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	as := newTestService(t)

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO1234567890abcd"
	challenge := pkceChallenge(verifier)

	ctx := contextWithTenant(t, "tenant-1")

	authResp, err := as.Authorize(ctx, AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "test-client",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "openid profile",
		State:               "xyz",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("authorize error: %v", err)
	}

	code := extractCode(t, authResp.RedirectURI)
	tokenResp, err := as.Token(ctx, TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     "test-client",
		CodeVerifier: verifier,
	})
	if err != nil {
		t.Fatalf("token error: %v", err)
	}
	if tokenResp.AccessToken == "" {
		t.Fatalf("expected access token")
	}
}

func TestTokenFailsWithInvalidVerifier(t *testing.T) {
	gin.SetMode(gin.TestMode)
	as := newTestService(t)

	verifier := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNO1234567890abcd"
	challenge := pkceChallenge(verifier)
	ctx := contextWithTenant(t, "tenant-1")

	authResp, err := as.Authorize(ctx, AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "test-client",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "openid profile",
		CodeChallenge:       challenge,
		CodeChallengeMethod: "S256",
	})
	if err != nil {
		t.Fatalf("authorize error: %v", err)
	}

	code := extractCode(t, authResp.RedirectURI)
	_, err = as.Token(ctx, TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  "https://app.example.com/callback",
		ClientID:     "test-client",
		CodeVerifier: "wrong-verifier-string-that-will-not-match" + verifier,
	})
	if err == nil {
		t.Fatalf("expected token exchange to fail")
	}
}

func TestAuthorizeRejectsUnknownClient(t *testing.T) {
	as := newTestService(t)
	ctx := contextWithTenant(t, "tenant-1")
	_, err := as.Authorize(ctx, AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "unknown",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "openid",
		CodeChallenge:       pkceChallenge("verifier"),
		CodeChallengeMethod: "S256",
	})
	if err != ErrInvalidClient {
		t.Fatalf("expected ErrInvalidClient, got %v", err)
	}
}

func TestAuthorizeRejectsInvalidRedirect(t *testing.T) {
	as := newTestService(t)
	ctx := contextWithTenant(t, "tenant-1")
	_, err := as.Authorize(ctx, AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "test-client",
		RedirectURI:         "https://evil.example.com/callback",
		Scope:               "openid",
		CodeChallenge:       pkceChallenge("verifier"),
		CodeChallengeMethod: "S256",
	})
	if err != ErrInvalidRedirectURI {
		t.Fatalf("expected ErrInvalidRedirectURI, got %v", err)
	}
}

func TestAuthorizeRejectsInvalidScope(t *testing.T) {
	as := newTestService(t)
	ctx := contextWithTenant(t, "tenant-1")
	_, err := as.Authorize(ctx, AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "test-client",
		RedirectURI:         "https://app.example.com/callback",
		Scope:               "admin",
		CodeChallenge:       pkceChallenge("verifier"),
		CodeChallengeMethod: "S256",
	})
	if err == nil || err.(*Error).Code != "invalid_scope" {
		t.Fatalf("expected invalid_scope error, got %v", err)
	}
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func extractCode(t *testing.T, redirect string) string {
	t.Helper()
	parsed, err := url.Parse(redirect)
	if err != nil {
		t.Fatalf("invalid redirect uri: %v", err)
	}
	code := parsed.Query().Get("code")
	if code == "" {
		t.Fatalf("missing code in redirect: %s", redirect)
	}
	return code
}

func contextWithTenant(t *testing.T, tenant string) context.Context {
	t.Helper()
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set(middleware.DefaultTenantHeader, tenant)
	c.Request = req
	middleware.TenantExtractor(middleware.TenantConfig{})(c)
	if c.IsAborted() {
		t.Fatalf("tenant extractor aborted request")
	}
	return c.Request.Context()
}

func newTestService(t *testing.T) *authService {
	t.Helper()
	svc, err := NewService(Config{
		DirectoryServiceURL: "http://dirsvc",
		Clients: []ClientConfig{
			{
				ID:            "test-client",
				TenantID:      "tenant-1",
				Name:          "Test Client",
				RedirectURIs:  []string{"https://app.example.com/callback"},
				AllowedScopes: []string{"openid", "profile"},
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create test service: %v", err)
	}
	return svc.(*authService)
}
