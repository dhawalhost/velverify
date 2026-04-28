package auth

import (
	"context"
	"testing"
)

func TestSocialTokenClientIDPrefersOIDCClientID(t *testing.T) {
	got := socialTokenClientID("google", "oidc-client-123")
	if got != "oidc-client-123" {
		t.Fatalf("expected oidc client id, got %s", got)
	}
}

func TestSocialTokenClientIDFallsBackToProvider(t *testing.T) {
	got := socialTokenClientID("google", "")
	if got != "social:google" {
		t.Fatalf("expected social:google, got %s", got)
	}
}

func TestSocialTokenClientIDFallsBackToUnknown(t *testing.T) {
	got := socialTokenClientID("   ", "")
	if got != "social:unknown" {
		t.Fatalf("expected social:unknown, got %s", got)
	}
}

func TestIssueTokensWithoutRefreshIncludesIDToken(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background() // Define context

	resp, err := svc.issueTokensWithoutRefresh(
		ctx, // Add context
		"admin-system",
		"social:google",
		"openid profile email",
		"user-123",
		"nonce-abc",
	)
	if err != nil {
		t.Fatalf("issueTokensWithoutRefresh returned error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatalf("expected access token")
	}
	if resp.IDToken == "" {
		t.Fatalf("expected id_token for openid scope")
	}
	if resp.RefreshToken != "" {
		t.Fatalf("expected no refresh_token, got %s", resp.RefreshToken)
	}
}

func TestIssueTokensWithoutRefreshSkipsIDTokenWithoutOpenID(t *testing.T) {
	svc := newTestService(t)

	resp, err := svc.issueTokensWithoutRefresh(
		context.Background(),
		"admin-system",
		"social:google",
		"profile email",
		"user-123",
		"",
	)
	if err != nil {
		t.Fatalf("issueTokensWithoutRefresh returned error: %v", err)
	}
	if resp.AccessToken == "" {
		t.Fatalf("expected access token")
	}
	if resp.IDToken != "" {
		t.Fatalf("expected no id_token when openid scope not requested")
	}
	if resp.RefreshToken != "" {
		t.Fatalf("expected no refresh_token, got %s", resp.RefreshToken)
	}
}
