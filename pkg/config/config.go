// Package config provides configuration management for WardSeal, aligned with gokit standards.
package config

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/viper"
	"github.com/subosito/gotenv"

	"github.com/dhawalhost/wardseal/pkg/types"
)

// Environment represents the deployment environment.
type Environment string

const (
	Development Environment = "development"
	Staging     Environment = "staging"
	Production  Environment = "production"
)

// Config is the top-level configuration for WardSeal services.
type Config struct {
	Environment   Environment         `mapstructure:"environment"`
	Database      DatabaseConfig      `mapstructure:"database"`
	Auth          AuthConfig          `mapstructure:"auth"`
	Directory     DirectoryConfig     `mapstructure:"directory"`
	Governance    GovernanceConfig    `mapstructure:"governance"`
	Observability ObservabilityConfig `mapstructure:"observability"`
	KMS           KMSConfig           `mapstructure:"kms"`
	License       LicenseConfig       `mapstructure:"license"`
	Slack         SlackConfig         `mapstructure:"slack"`
}

// DatabaseConfig holds PostgreSQL connection settings.
type DatabaseConfig struct {
	Host     string       `mapstructure:"host"`
	Port     int          `mapstructure:"port"`
	User     string       `mapstructure:"user"`
	Password types.Secret `mapstructure:"password"` // Populated by Vault or Env
	Name     string       `mapstructure:"name"`
	SSLMode  string       `mapstructure:"sslmode"`
}

// ConnectionString returns the PostgreSQL connection string.
func (d DatabaseConfig) ConnectionString() string {
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		d.User, d.Password.Raw(), d.Host, d.Port, d.Name, d.SSLMode)
}

// AuthConfig holds auth service settings.
type AuthConfig struct {
	BaseURL             string           `mapstructure:"base_url"`
	DirectoryServiceURL string           `mapstructure:"directory_service_url"`
	ServiceAuthToken    types.Secret     `mapstructure:"service_auth_token"`
	ServiceAuthHeader   string           `mapstructure:"service_auth_header"`
	JWTPrivateKeyPath   string           `mapstructure:"jwt_private_key_path"`
	JWTPublicKeyPath    string           `mapstructure:"jwt_public_key_path"`
	DeploymentMode      string           `mapstructure:"deployment_mode"`
	UIURL               string           `mapstructure:"ui_url"`
	RedisAddr           string           `mapstructure:"redis_addr"`
	RedisPassword       types.Secret     `mapstructure:"redis_password"`
	RedisDB             int              `mapstructure:"redis_db"`
	CookieDomain        string           `mapstructure:"cookie_domain"`
	WebAuthnSessionTTL  time.Duration    `mapstructure:"webauthn_session_ttl"`
	RateLimitUseTenant  bool             `mapstructure:"rate_limit_use_tenant"`
	RateLimitKeyPrefix  string           `mapstructure:"rate_limit_key_prefix"`
	RateLimitDefault    RateLimitProfile `mapstructure:"rate_limit_default"`
	RateLimitLogin      RateLimitProfile `mapstructure:"rate_limit_login"`
	RateLimitToken      RateLimitProfile `mapstructure:"rate_limit_token"`
	RateLimitSetup      RateLimitProfile `mapstructure:"rate_limit_setup"`
	RateLimitWebhook    RateLimitProfile `mapstructure:"rate_limit_webhook"`
	RateLimitDegraded   RateLimitProfile `mapstructure:"rate_limit_degraded"`
}

type RateLimitProfile struct {
	Requests int           `mapstructure:"requests"`
	Window   time.Duration `mapstructure:"window"`
}

type DirectoryConfig struct {
	ServiceAuthToken  types.Secret `mapstructure:"service_auth_token"`
	ServiceAuthHeader string       `mapstructure:"service_auth_header"`
}

type GovernanceConfig struct {
	DirectoryServiceURL string       `mapstructure:"directory_service_url"`
	WebhookSecret       types.Secret `mapstructure:"webhook_secret"`
	CORSAllowedOrigins  []string     `mapstructure:"cors_allowed_origins"`
}

type ObservabilityConfig struct {
	OTELEndpoint   string `mapstructure:"otel_endpoint"`
	ServiceName    string `mapstructure:"service_name"`
	ServiceVersion string `mapstructure:"service_version"`
	LogLevel       string `mapstructure:"log_level"`
}

type LicenseConfig struct {
	Required      bool         `mapstructure:"required"`
	Key           types.Secret `mapstructure:"key"`
	PublicKeyPath string       `mapstructure:"public_key_path"`
}

type KMSConfig struct {
	Provider       string       `mapstructure:"provider"`
	PrivateKeyPath string       `mapstructure:"private_key_path"`
	PublicKeyPath  string       `mapstructure:"public_key_path"`
	MasterKey      types.Secret `mapstructure:"master_key"` // Used for symmetric encryption (AES-256-GCM)
	VaultAddr      string       `mapstructure:"vault_addr"`
	VaultToken     types.Secret `mapstructure:"vault_token"`
	VaultKeyName   string       `mapstructure:"vault_key_name"`
	VaultKeyPath   string       `mapstructure:"vault_key_path"`
	VaultNamespace string       `mapstructure:"vault_namespace"`
	VaultRoleID    string       `mapstructure:"vault_role_id"`
	VaultSecretID  types.Secret `mapstructure:"vault_secret_id"`
}

type SlackConfig struct {
	Enabled    bool         `mapstructure:"enabled"`
	WebhookURL types.Secret `mapstructure:"webhook_url"`
	AppToken   types.Secret `mapstructure:"app_token"`
	BotToken   types.Secret `mapstructure:"bot_token"`
	ChannelID  string       `mapstructure:"channel_id"`
}

// Load reads configuration using Viper, aligned with gokit patterns.
func Load(cfgFile string) (*Config, error) {
	v := viper.New()

	// Defaults (Matches gokit/config where applicable)
	v.SetDefault("environment", "development")
	v.SetDefault("database.host", "localhost")
	v.SetDefault("database.port", 5432)
	v.SetDefault("database.user", "user")
	v.SetDefault("database.name", "identity_platform")
	v.SetDefault("database.sslmode", "disable")

	v.SetDefault("auth.base_url", "http://localhost:8080")
	v.SetDefault("auth.directory_service_url", "http://localhost:8081")
	v.SetDefault("auth.service_auth_header", "X-Service-Token")
	v.SetDefault("auth.rate_limit_use_tenant", true)
	v.SetDefault("auth.rate_limit_key_prefix", "authsvc:ratelimit")

	v.SetDefault("observability.log_level", "info")
	v.SetDefault("kms.provider", "local")
	v.SetDefault("kms.vault_key_name", "wardseal-signing-key")
	v.SetDefault("kms.vault_key_path", "transit")

	v.SetDefault("slack.enabled", false)
	v.SetDefault("governance.cors_allowed_origins", []string{"http://localhost:5173"})

	// Environment variables
	v.SetEnvPrefix("APP") // Align with gokit default prefix
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()
	// Explicitly bind environment variables for keys that don't have defaults but are required
	_ = v.BindEnv("database.user")
	_ = v.BindEnv("database.password")
	_ = v.BindEnv("database.name")
	_ = v.BindEnv("auth.base_url")
	_ = v.BindEnv("auth.directory_service_url")
	_ = v.BindEnv("auth.deployment_mode")
	_ = v.BindEnv("auth.ui_url")
	_ = v.BindEnv("auth.service_auth_token")
	_ = v.BindEnv("auth.jwt_private_key_path")
	_ = v.BindEnv("auth.jwt_public_key_path")
	_ = v.BindEnv("auth.redis_addr")
	_ = v.BindEnv("auth.cookie_domain")
	_ = v.BindEnv("directory.service_auth_token")
	_ = v.BindEnv("governance.directory_service_url")
	_ = v.BindEnv("governance.webhook_secret")
	_ = v.BindEnv("governance.cors_allowed_origins")
	_ = v.BindEnv("kms.provider")
	_ = v.BindEnv("kms.master_key")
	_ = v.BindEnv("kms.private_key_path")
	_ = v.BindEnv("kms.public_key_path")
	_ = v.BindEnv("kms.vault_addr")
	_ = v.BindEnv("kms.vault_token")
	_ = v.BindEnv("kms.vault_key_name")
	_ = v.BindEnv("kms.vault_key_path")
	_ = v.BindEnv("kms.vault_namespace")
	_ = v.BindEnv("kms.vault_role_id")
	_ = v.BindEnv("kms.vault_secret_id")
	_ = v.BindEnv("observability.otel_endpoint")
	_ = v.BindEnv("observability.service_name")
	_ = v.BindEnv("observability.service_version")
	_ = v.BindEnv("observability.log_level")

	// Optional config file
	if cfgFile != "" {
		if strings.HasSuffix(cfgFile, ".env") || filepath.Base(cfgFile) == ".env" {
			if err := gotenv.Load(cfgFile); err != nil {
				return nil, fmt.Errorf("config: load env file: %w", err)
			}
		} else {
			v.SetConfigFile(cfgFile)
			if err := v.ReadInConfig(); err != nil {
				return nil, fmt.Errorf("config: read config file: %w", err)
			}
		}
	} else {
		// Try to load standard .env if no file provided
		_ = gotenv.Load(".env")
	}

	var cfg Config
	if err := v.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	// Post-processing: Vault integration
	// Post-processing: Vault integration
	if cfg.KMS.VaultAddr != "" {
		// Late-binding from Vault is handled dynamically in the KMS package.
		// No immediate action needed here during initialization sweep.
		_ = cfg.KMS.VaultAddr
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// MustLoad is like Load but panics on error.
func MustLoad() *Config {
	cfgFile := os.Getenv("APP_CONFIG")
	if cfgFile == "" {
		cfgFile = os.Getenv("CONFIG_FILE")
	}

	cfg, err := Load(cfgFile)
	if err != nil {
		panic(fmt.Sprintf("config: MustLoad: %v", err))
	}
	return cfg
}

func (c *Config) Validate() error {
	var problems []string

	if err := validateAbsoluteURL(c.Auth.BaseURL, false); err != nil {
		problems = append(problems, fmt.Sprintf("AUTH_SERVICE_URL invalid: %v", err))
	}

	if err := validateAbsoluteURL(c.Auth.UIURL, false); err != nil {
		problems = append(problems, fmt.Sprintf("UI_URL invalid: %v", err))
	}

	for _, origin := range c.Governance.CORSAllowedOrigins {
		u, err := url.Parse(origin)
		if err != nil || u.Path != "" {
			problems = append(problems, fmt.Sprintf("CORS_ALLOWED_ORIGIN '%s' is invalid or contains a path", origin))
		}
	}

	if c.Environment == Staging || c.Environment == Production {
		if err := validateAbsoluteURL(c.Auth.BaseURL, true); err != nil {
			problems = append(problems, fmt.Sprintf("AUTH_SERVICE_URL must be https in %s: %v", c.Environment, err))
		}

		if !strings.EqualFold(c.KMS.Provider, "vault") {
			problems = append(problems, fmt.Sprintf("KMS_PROVIDER must be 'vault' in %s", c.Environment))
		}

		if c.KMS.VaultAddr == "" {
			problems = append(problems, fmt.Sprintf("VAULT_ADDR is required in %s", c.Environment))
		}

		hasAuth := !c.KMS.VaultToken.IsEmpty() || (c.KMS.VaultRoleID != "" && !c.KMS.VaultSecretID.IsEmpty())
		if !hasAuth {
			problems = append(problems, fmt.Sprintf("Vault authentication is required in %s", c.Environment))
		}
		if c.Database.SSLMode == "disable" {
			problems = append(problems, fmt.Sprintf("database.sslmode cannot be 'disable' in %s environment", c.Environment))
		}
	} else {
		// In development/local mode, ensure master key is 32 bytes for AES-256
		if c.KMS.Provider == "local" || c.KMS.Provider == "" {
			if !c.KMS.MasterKey.IsEmpty() && len(c.KMS.MasterKey.Raw()) != 32 {
				problems = append(problems, "KMS_MASTER_KEY must be exactly 32 bytes for local AES-256 encryption")
			}
		}

		// Ensure JWT paths are set for the "local" environment (as expected by tests)
		if c.Environment == "local" {
			if c.Auth.JWTPrivateKeyPath == "" || c.Auth.JWTPublicKeyPath == "" {
				problems = append(problems, "JWT_PRIVATE_KEY_PATH and JWT_PUBLIC_KEY_PATH are required in local")
			}
		}
	}

	if len(problems) > 0 {
		return fmt.Errorf("configuration validation failed: %s", strings.Join(problems, "; "))
	}

	return nil
}

func validateAbsoluteURL(raw string, requireHTTPS bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("must be an absolute URL with host")
	}
	scheme := strings.ToLower(u.Scheme)
	if requireHTTPS && scheme != "https" {
		return fmt.Errorf("scheme must be https")
	}
	return nil
}
