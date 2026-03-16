// Package config provides unified configuration management for WardSeal services.
// It loads configuration from multiple sources in order of priority:
//  1. Default values (built-in)
//  2. .env.defaults file (non-secrets, checked into git)
//  3. .env.{environment} file (environment-specific non-secrets)
//  4. HashiCorp Vault (secrets only, if VAULT_ADDR is set)
//  5. OS environment variables (highest priority overrides)
package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Environment represents the deployment environment.
type Environment string

const (
	Development Environment = "development"
	Staging     Environment = "staging"
	Production  Environment = "production"
)

// Config holds all configuration for WardSeal services.
type Config struct {
	// Environment is the current deployment environment.
	Environment Environment

	// Database configuration
	Database DatabaseConfig

	// Auth service configuration
	Auth AuthConfig

	// Directory service configuration
	Directory DirectoryConfig

	// Governance service configuration
	Governance GovernanceConfig

	// Observability configuration
	Observability ObservabilityConfig

	// KMS configuration
	KMS KMSConfig

	// License configuration (Enterprise)
	License LicenseConfig
}

// DatabaseConfig holds database connection settings.
type DatabaseConfig struct {
	Host     string
	Port     int
	User     string
	Password string // From Vault
	Name     string
	SSLMode  string
}

// ConnectionString returns the PostgreSQL connection string.
func (d DatabaseConfig) ConnectionString() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password, d.Host, d.Port, d.Name, d.SSLMode)
}

// AuthConfig holds auth service settings.
type AuthConfig struct {
	BaseURL             string
	DirectoryServiceURL string
	ServiceAuthToken    string // From Vault
	ServiceAuthHeader   string
	JWTPrivateKeyPath   string
	JWTPublicKeyPath    string
	DeploymentMode      string
	UIURL               string
	RedisAddr           string
	RedisPassword       string
	RedisDB             int
	WebAuthnSessionTTL  time.Duration
	RateLimitUseTenant  bool
	RateLimitKeyPrefix  string
	RateLimitDefault    RateLimitProfile
	RateLimitLogin      RateLimitProfile
	RateLimitToken      RateLimitProfile
	RateLimitSetup      RateLimitProfile
	RateLimitWebhook    RateLimitProfile
	RateLimitDegraded   RateLimitProfile
}

// RateLimitProfile configures a request budget for a time window.
type RateLimitProfile struct {
	Requests int
	Window   time.Duration
}

// DirectoryConfig holds directory service settings.
type DirectoryConfig struct {
	ServiceAuthToken  string // From Vault
	ServiceAuthHeader string
}

// GovernanceConfig holds governance service settings.
type GovernanceConfig struct {
	DirectoryServiceURL string
	WebhookSecret       string // From Vault
	CORSAllowedOrigins  []string
}

// ObservabilityConfig holds observability settings.
type ObservabilityConfig struct {
	OTELEndpoint   string
	ServiceName    string
	ServiceVersion string
	LogLevel       string
}

// LicenseConfig holds enterprise license settings.
type LicenseConfig struct {
	Required      bool
	Key           string // From Vault
	PublicKeyPath string
}

// KMSConfig holds settings for Key Management Service (Vault or Local).
type KMSConfig struct {
	Provider       string
	PrivateKeyPath string
	PublicKeyPath  string
	VaultAddr      string
	VaultToken     string
	VaultKeyName   string
	VaultKeyPath   string
	VaultNamespace string
	VaultRoleID    string
	VaultSecretID  string
}

// Loader handles configuration loading from multiple sources.
type Loader struct {
	environment Environment
	vaultClient VaultClient
	values      map[string]string
}

// VaultClient interface for Vault operations (allows mocking).
type VaultClient interface {
	ReadSecret(path string) (map[string]string, error)
	Close() error
}

// LoaderOption configures the loader.
type LoaderOption func(*Loader)

// WithEnvironment sets the environment explicitly.
func WithEnvironment(env Environment) LoaderOption {
	return func(l *Loader) {
		l.environment = env
	}
}

// WithVaultClient sets a custom Vault client.
func WithVaultClient(client VaultClient) LoaderOption {
	return func(l *Loader) {
		l.vaultClient = client
	}
}

// NewLoader creates a new configuration loader.
func NewLoader(opts ...LoaderOption) *Loader {
	l := &Loader{
		values: make(map[string]string),
	}

	// Apply options
	for _, opt := range opts {
		opt(l)
	}

	// Detect environment if not set
	if l.environment == "" {
		l.environment = detectEnvironment()
	}

	return l
}

// Load loads configuration from all sources.
func (l *Loader) Load() (*Config, error) {
	// 1. Load defaults
	l.loadDefaults()

	// 2. Load .env.defaults file
	if err := l.loadEnvFile("config/.env.defaults"); err != nil {
		// Not an error if file doesn't exist
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load .env.defaults: %w", err)
		}
	}

	// 3. Load environment-specific .env file
	envFile := fmt.Sprintf("config/.env.%s", l.environment)
	if err := l.loadEnvFile(envFile); err != nil {
		if !os.IsNotExist(err) {
			return nil, fmt.Errorf("failed to load %s: %w", envFile, err)
		}
	}

	// 4. Load secrets from Vault (if configured)
	if vaultAddr := os.Getenv("VAULT_ADDR"); vaultAddr != "" {
		if err := l.loadFromVault(); err != nil {
			// Log warning but don't fail - allow fallback to env vars
			fmt.Printf("[WARN] Failed to load secrets from Vault: %v\n", err)
		}
	}

	// 5. Load OS environment variables (highest priority)
	l.loadOSEnv()

	// Build config struct
	return l.buildConfig()
}

// loadDefaults sets built-in default values.
func (l *Loader) loadDefaults() {
	defaults := map[string]string{
		"ENVIRONMENT":                        "development",
		"DB_HOST":                            "localhost",
		"DB_PORT":                            "5432",
		"DB_USER":                            "user",
		"DB_PASSWORD":                        "password",
		"DB_NAME":                            "identity_platform",
		"DB_SSLMODE":                         "disable",
		"AUTH_SERVICE_URL":                   "http://localhost:8080",
		"DIRECTORY_SERVICE_URL":              "http://localhost:8081",
		"SERVICE_AUTH_HEADER":                "X-Service-Auth",
		"LOG_LEVEL":                          "info",
		"KMS_PROVIDER":                       "local",
		"VAULT_KEY_NAME":                     "wardseal-signing-key",
		"VAULT_KEY_PATH":                     "transit",
		"UI_URL":                             "http://localhost:5173",
		"RATE_LIMIT_USE_TENANT":              "true",
		"RATE_LIMIT_KEY_PREFIX":              "authsvc:ratelimit",
		"RATE_LIMIT_DEFAULT_REQUESTS":        "1200",
		"RATE_LIMIT_DEFAULT_WINDOW_SECONDS":  "60",
		"RATE_LIMIT_LOGIN_REQUESTS":          "60",
		"RATE_LIMIT_LOGIN_WINDOW_SECONDS":    "60",
		"RATE_LIMIT_TOKEN_REQUESTS":          "240",
		"RATE_LIMIT_TOKEN_WINDOW_SECONDS":    "60",
		"RATE_LIMIT_SETUP_REQUESTS":          "30",
		"RATE_LIMIT_SETUP_WINDOW_SECONDS":    "60",
		"RATE_LIMIT_WEBHOOK_REQUESTS":        "600",
		"RATE_LIMIT_WEBHOOK_WINDOW_SECONDS":  "60",
		"RATE_LIMIT_DEGRADED_REQUESTS":       "30",
		"RATE_LIMIT_DEGRADED_WINDOW_SECONDS": "60",
	}

	for k, v := range defaults {
		l.values[k] = v
	}
}

// loadEnvFile loads a .env file.
func (l *Loader) loadEnvFile(path string) error {
	data, err := os.ReadFile(path) //nolint:gosec // G304: paths are from trusted sources (.env files)
	if err != nil {
		return err
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=value
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		value = strings.Trim(value, `"'`)

		l.values[key] = value
	}

	return nil
}

// loadFromVault loads secrets from HashiCorp Vault.
func (l *Loader) loadFromVault() error {
	// Create Vault client if not provided
	if l.vaultClient == nil {
		client, err := newVaultClient()
		if err != nil {
			return err
		}
		l.vaultClient = client
	}

	// Read secrets for current environment
	secretPath := fmt.Sprintf("secret/data/wardseal/%s", l.environment)
	secrets, err := l.vaultClient.ReadSecret(secretPath)
	if err != nil {
		return err
	}

	// Merge secrets into values
	for k, v := range secrets {
		l.values[k] = v
	}

	return nil
}

// loadOSEnv loads OS environment variables (highest priority).
func (l *Loader) loadOSEnv() {
	// List of environment variables to check
	envVars := []string{
		"ENVIRONMENT",
		"DB_HOST", "DB_PORT", "DB_USER", "DB_PASSWORD", "DB_NAME", "DB_SSLMODE",
		"AUTH_SERVICE_URL", "DIRECTORY_SERVICE_URL",
		"SERVICE_AUTH_TOKEN", "SERVICE_AUTH_HEADER",
		"REDIS_ADDR", "REDIS_PASSWORD", "REDIS_DB", "WEBAUTHN_SESSION_TTL_SECONDS",
		"RATE_LIMIT_USE_TENANT", "RATE_LIMIT_KEY_PREFIX",
		"RATE_LIMIT_DEFAULT_REQUESTS", "RATE_LIMIT_DEFAULT_WINDOW_SECONDS",
		"RATE_LIMIT_LOGIN_REQUESTS", "RATE_LIMIT_LOGIN_WINDOW_SECONDS",
		"RATE_LIMIT_TOKEN_REQUESTS", "RATE_LIMIT_TOKEN_WINDOW_SECONDS",
		"RATE_LIMIT_SETUP_REQUESTS", "RATE_LIMIT_SETUP_WINDOW_SECONDS",
		"RATE_LIMIT_WEBHOOK_REQUESTS", "RATE_LIMIT_WEBHOOK_WINDOW_SECONDS",
		"RATE_LIMIT_DEGRADED_REQUESTS", "RATE_LIMIT_DEGRADED_WINDOW_SECONDS",
		"JWT_PRIVATE_KEY_PATH", "JWT_PUBLIC_KEY_PATH",
		"WEBHOOK_SECRET",
		"OTEL_EXPORTER_OTLP_ENDPOINT", "OTEL_SERVICE_NAME",
		"LOG_LEVEL",
		"REQUIRE_LICENSE", "LICENSE_KEY", "LICENSE_PUBLIC_KEY_PATH",
		"CORS_ALLOWED_ORIGINS",
		"KMS_PROVIDER", "VAULT_ADDR", "VAULT_TOKEN", "VAULT_KEY_NAME",
		"VAULT_KEY_PATH", "VAULT_NAMESPACE", "VAULT_ROLE_ID", "VAULT_SECRET_ID",
		"DEPLOYMENT_MODE",
		"UI_URL",
	}

	for _, key := range envVars {
		if value := os.Getenv(key); value != "" {
			l.values[key] = value
		}
	}
}

// buildConfig constructs the Config struct from loaded values.
func (l *Loader) buildConfig() (*Config, error) {
	dbPort, _ := strconv.Atoi(l.get("DB_PORT", "5432"))
	redisDB, _ := strconv.Atoi(l.get("REDIS_DB", "0"))
	webAuthnSessionTTLSeconds, _ := strconv.Atoi(l.get("WEBAUTHN_SESSION_TTL_SECONDS", "600"))
	rateLimitDefaultRequests, _ := strconv.Atoi(l.get("RATE_LIMIT_DEFAULT_REQUESTS", "1200"))
	rateLimitDefaultWindowSeconds, _ := strconv.Atoi(l.get("RATE_LIMIT_DEFAULT_WINDOW_SECONDS", "60"))
	rateLimitLoginRequests, _ := strconv.Atoi(l.get("RATE_LIMIT_LOGIN_REQUESTS", "60"))
	rateLimitLoginWindowSeconds, _ := strconv.Atoi(l.get("RATE_LIMIT_LOGIN_WINDOW_SECONDS", "60"))
	rateLimitTokenRequests, _ := strconv.Atoi(l.get("RATE_LIMIT_TOKEN_REQUESTS", "240"))
	rateLimitTokenWindowSeconds, _ := strconv.Atoi(l.get("RATE_LIMIT_TOKEN_WINDOW_SECONDS", "60"))
	rateLimitSetupRequests, _ := strconv.Atoi(l.get("RATE_LIMIT_SETUP_REQUESTS", "30"))
	rateLimitSetupWindowSeconds, _ := strconv.Atoi(l.get("RATE_LIMIT_SETUP_WINDOW_SECONDS", "60"))
	rateLimitWebhookRequests, _ := strconv.Atoi(l.get("RATE_LIMIT_WEBHOOK_REQUESTS", "600"))
	rateLimitWebhookWindowSeconds, _ := strconv.Atoi(l.get("RATE_LIMIT_WEBHOOK_WINDOW_SECONDS", "60"))
	rateLimitDegradedRequests, _ := strconv.Atoi(l.get("RATE_LIMIT_DEGRADED_REQUESTS", "30"))
	rateLimitDegradedWindowSeconds, _ := strconv.Atoi(l.get("RATE_LIMIT_DEGRADED_WINDOW_SECONDS", "60"))

	cfg := &Config{
		Environment: Environment(l.get("ENVIRONMENT", "development")),

		Database: DatabaseConfig{
			Host:     l.get("DB_HOST", "localhost"),
			Port:     dbPort,
			User:     l.get("DB_USER", "user"),
			Password: l.get("DB_PASSWORD", ""),
			Name:     l.get("DB_NAME", "identity_platform"),
			SSLMode:  l.get("DB_SSLMODE", "disable"),
		},

		Auth: AuthConfig{
			BaseURL:             l.get("AUTH_SERVICE_URL", "http://localhost:8080"),
			DirectoryServiceURL: l.get("DIRECTORY_SERVICE_URL", "http://localhost:8081"),
			ServiceAuthToken:    l.get("SERVICE_AUTH_TOKEN", ""),
			ServiceAuthHeader:   l.get("SERVICE_AUTH_HEADER", "X-Service-Auth"),
			JWTPrivateKeyPath:   l.get("JWT_PRIVATE_KEY_PATH", ""),
			JWTPublicKeyPath:    l.get("JWT_PUBLIC_KEY_PATH", ""),
			DeploymentMode:      l.get("DEPLOYMENT_MODE", "selfhost"),
			UIURL:               l.get("UI_URL", "http://localhost:5173"),
			RedisAddr:           l.get("REDIS_ADDR", ""),
			RedisPassword:       l.get("REDIS_PASSWORD", ""),
			RedisDB:             redisDB,
			WebAuthnSessionTTL:  time.Duration(webAuthnSessionTTLSeconds) * time.Second,
			RateLimitUseTenant:  strings.EqualFold(l.get("RATE_LIMIT_USE_TENANT", "true"), "true"),
			RateLimitKeyPrefix:  l.get("RATE_LIMIT_KEY_PREFIX", "authsvc:ratelimit"),
			RateLimitDefault: RateLimitProfile{
				Requests: rateLimitDefaultRequests,
				Window:   time.Duration(rateLimitDefaultWindowSeconds) * time.Second,
			},
			RateLimitLogin: RateLimitProfile{
				Requests: rateLimitLoginRequests,
				Window:   time.Duration(rateLimitLoginWindowSeconds) * time.Second,
			},
			RateLimitToken: RateLimitProfile{
				Requests: rateLimitTokenRequests,
				Window:   time.Duration(rateLimitTokenWindowSeconds) * time.Second,
			},
			RateLimitSetup: RateLimitProfile{
				Requests: rateLimitSetupRequests,
				Window:   time.Duration(rateLimitSetupWindowSeconds) * time.Second,
			},
			RateLimitWebhook: RateLimitProfile{
				Requests: rateLimitWebhookRequests,
				Window:   time.Duration(rateLimitWebhookWindowSeconds) * time.Second,
			},
			RateLimitDegraded: RateLimitProfile{
				Requests: rateLimitDegradedRequests,
				Window:   time.Duration(rateLimitDegradedWindowSeconds) * time.Second,
			},
		},

		Directory: DirectoryConfig{
			ServiceAuthToken:  l.get("SERVICE_AUTH_TOKEN", ""),
			ServiceAuthHeader: l.get("SERVICE_AUTH_HEADER", "X-Service-Auth"),
		},

		Governance: GovernanceConfig{
			DirectoryServiceURL: l.get("DIRECTORY_SERVICE_URL", "http://localhost:8081"),
			WebhookSecret:       l.get("WEBHOOK_SECRET", ""),
			CORSAllowedOrigins:  l.getList("CORS_ALLOWED_ORIGINS"),
		},

		Observability: ObservabilityConfig{
			OTELEndpoint:   l.get("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
			ServiceName:    l.get("OTEL_SERVICE_NAME", ""),
			ServiceVersion: "1.0.0",
			LogLevel:       l.get("LOG_LEVEL", "info"),
		},

		License: LicenseConfig{
			Required:      l.get("REQUIRE_LICENSE", "false") == "true",
			Key:           l.get("LICENSE_KEY", ""),
			PublicKeyPath: l.get("LICENSE_PUBLIC_KEY_PATH", "/etc/wardseal/license_public.pem"),
		},

		KMS: KMSConfig{
			Provider:       l.get("KMS_PROVIDER", "local"),
			PrivateKeyPath: l.get("JWT_PRIVATE_KEY_PATH", ""),
			PublicKeyPath:  l.get("JWT_PUBLIC_KEY_PATH", ""),
			VaultAddr:      l.get("VAULT_ADDR", ""),
			VaultToken:     l.get("VAULT_TOKEN", ""),
			VaultKeyName:   l.get("VAULT_KEY_NAME", "wardseal-signing-key"),
			VaultKeyPath:   l.get("VAULT_KEY_PATH", "transit"),
			VaultNamespace: l.get("VAULT_NAMESPACE", ""),
			VaultRoleID:    l.get("VAULT_ROLE_ID", ""),
			VaultSecretID:  l.get("VAULT_SECRET_ID", ""),
		},
	}

	return cfg, nil
}

// get returns a value or default.
func (l *Loader) get(key, defaultValue string) string {
	if v, ok := l.values[key]; ok && v != "" {
		return v
	}
	return defaultValue
}

// getList returns a comma-separated value as a slice.
func (l *Loader) getList(key string) []string {
	value := l.get(key, "")
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			result = append(result, trimmed)
		}
	}
	return result
}

// detectEnvironment determines the current environment.
func detectEnvironment() Environment {
	env := os.Getenv("ENVIRONMENT")
	switch strings.ToLower(env) {
	case "production", "prod":
		return Production
	case "staging", "stage":
		return Staging
	default:
		return Development
	}
}

// Load is a convenience function that creates a loader and loads config.
func Load(opts ...LoaderOption) (*Config, error) {
	return NewLoader(opts...).Load()
}

// MustLoad loads config or panics.
func MustLoad(opts ...LoaderOption) *Config {
	cfg, err := Load(opts...)
	if err != nil {
		panic(fmt.Sprintf("failed to load config: %v", err))
	}
	return cfg
}

// Refresh reloads configuration (useful for secret rotation).
func (l *Loader) Refresh() (*Config, error) {
	// Clear current values except OS env
	l.values = make(map[string]string)
	return l.Load()
}

// StartAutoRefresh starts a goroutine that refreshes config periodically.
func (l *Loader) StartAutoRefresh(interval time.Duration, callback func(*Config)) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for range ticker.C {
			if cfg, err := l.Refresh(); err == nil {
				callback(cfg)
			}
		}
	}()
}
