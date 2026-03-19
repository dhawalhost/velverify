package config

import "testing"

func TestValidate_AllowsDevelopmentHTTP(t *testing.T) {
	cfg := &Config{
		Environment: Development,
		Auth: AuthConfig{
			BaseURL: "http://auth.wardseal.local",
			UIURL:   "http://manage.wardseal.local",
		},
		Governance: GovernanceConfig{
			CORSAllowedOrigins: []string{"http://manage.wardseal.local", "http://wardseal.local"},
		},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected development config to validate, got error: %v", err)
	}
}

func TestValidate_RejectsInvalidUIURL(t *testing.T) {
	cfg := &Config{
		Environment: Development,
		Auth: AuthConfig{
			BaseURL: "http://auth.wardseal.local",
			UIURL:   "manage.wardseal.local",
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for invalid UI_URL")
	}
}

func TestValidate_RequiresHTTPSInStaging(t *testing.T) {
	cfg := &Config{
		Environment: Staging,
		Auth: AuthConfig{
			BaseURL: "http://auth-staging.wardseal.com",
			UIURL:   "https://manage-staging.wardseal.com",
		},
		KMS: KMSConfig{Provider: "vault"},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for non-https AUTH_SERVICE_URL in staging")
	}
}

func TestValidate_RequiresVaultKMSInProduction(t *testing.T) {
	cfg := &Config{
		Environment: Production,
		Auth: AuthConfig{
			BaseURL: "https://auth.wardseal.com",
			UIURL:   "https://manage.wardseal.com",
		},
		KMS: KMSConfig{Provider: "local"},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for non-vault KMS in production")
	}
}

func TestValidate_RequiresJWTPathsInLocal(t *testing.T) {
	cfg := &Config{
		Environment: Environment("local"),
		Auth: AuthConfig{
			BaseURL: "http://auth.wardseal.local",
			UIURL:   "http://manage.wardseal.local",
		},
		KMS: KMSConfig{Provider: "local"},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error when JWT key paths are missing in local")
	}
}

func TestValidate_AllowsLocalWithJWTPaths(t *testing.T) {
	cfg := &Config{
		Environment: Environment("local"),
		Auth: AuthConfig{
			BaseURL:           "http://auth.wardseal.local",
			UIURL:             "http://manage.wardseal.local",
			JWTPrivateKeyPath: "/etc/wardseal/keys/private_key.pem",
			JWTPublicKeyPath:  "/etc/wardseal/keys/public_key.pem",
		},
		KMS: KMSConfig{Provider: "local"},
	}

	if err := cfg.Validate(); err != nil {
		t.Fatalf("expected local config with JWT paths to validate, got error: %v", err)
	}
}

func TestValidate_RejectsCORSOriginWithPath(t *testing.T) {
	cfg := &Config{
		Environment: Development,
		Auth: AuthConfig{
			BaseURL: "http://auth.wardseal.local",
			UIURL:   "http://manage.wardseal.local",
		},
		Governance: GovernanceConfig{
			CORSAllowedOrigins: []string{"http://manage.wardseal.local/app"},
		},
	}

	if err := cfg.Validate(); err == nil {
		t.Fatal("expected validation error for CORS origin containing a path")
	}
}
