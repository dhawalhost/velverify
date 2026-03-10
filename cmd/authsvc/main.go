package main

import (
	"context"
	"os"
	"strings"

	"github.com/dhawalhost/wardseal/internal/auth"
	"github.com/dhawalhost/wardseal/internal/license"
	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/saml"
	"github.com/dhawalhost/wardseal/pkg/config"
	"github.com/dhawalhost/wardseal/pkg/database"
	"github.com/dhawalhost/wardseal/pkg/kms"
	"github.com/dhawalhost/wardseal/pkg/logger"
	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/dhawalhost/wardseal/pkg/observability"
	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

func main() {
	log := logger.NewFromEnv()
	defer func() { _ = log.Sync() }()

	// Load centralized configuration (handles defaults, .env, OS env, and Vault)
	cfg := config.MustLoad()

	// Enterprise License Verification
	if cfg.License.Required {
		log.Info("Checking Enterprise License...")

		pubKey, err := os.ReadFile(cfg.License.PublicKeyPath) //nolint:gosec // G304: path is from trusted config
		if err != nil {
			log.Fatal("Failed to read license public key", zap.Error(err))
		}

		mgr, err := license.NewManager(pubKey)
		if err != nil {
			log.Fatal("Failed to initialize license manager", zap.Error(err))
		}

		if cfg.License.Key == "" {
			log.Fatal("LICENSE_KEY environment variable/vault secret is required for enterprise edition")
		}

		lic, err := mgr.Verify(cfg.License.Key)
		if err != nil {
			log.Fatal("Invalid license key", zap.Error(err))
		}

		log.Info("Enterprise License Verified",
			zap.String("customer", lic.CustomerName),
			zap.Time("expires_at", lic.ExpiresAt),
			zap.String("plan", lic.Plan))
	}

	directoryServiceURL := cfg.Auth.DirectoryServiceURL
	serviceToken := cfg.Auth.ServiceAuthToken
	if serviceToken == "" {
		serviceToken = "dev-internal-token" //nolint:gosec // G101: dev-only fallback, not production credentials
		log.Warn("SERVICE_AUTH_TOKEN not set, using development default")
	}
	serviceHeader := cfg.Auth.ServiceAuthHeader

	dbConfig := database.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password, // Securely injected by Vault if configured
		DBName:   cfg.Database.Name,
		SSLMode:  cfg.Database.SSLMode,
	}

	db, err := database.NewConnection(dbConfig)
	if err != nil {
		log.Error("Failed to connect to database", zap.Error(err))
		os.Exit(1)
	}
	clientStore := oauthclient.NewRepository(db)
	samlStore := saml.NewStore(db)
	deviceStore := auth.NewDeviceStore(db)
	signalStore := auth.NewSignalStore(db)
	webauthnStore := auth.NewWebAuthnRepository(db)
	brandingStore := auth.NewBrandingStore(db)
	ssoProviderStore := auth.NewSQLSSOProviderStore(db)

	authServiceURL := cfg.Auth.BaseURL

	// Initialize persistent stores for production durability
	codeStore := auth.NewSQLAuthorizationCodeStore(db)
	refreshStore := auth.NewSQLRefreshTokenStore(db)
	revocationStore := auth.NewSQLRevocationStore(db)
	totpStore := auth.NewTOTPStore(db)

	// Initialize Key Management Service
	kmsConfig := kms.Config{
		Provider:       cfg.KMS.Provider,
		PrivateKeyPath: cfg.KMS.PrivateKeyPath,
		PublicKeyPath:  cfg.KMS.PublicKeyPath,
		VaultAddr:      cfg.KMS.VaultAddr,
		VaultToken:     cfg.KMS.VaultToken,
		VaultKeyName:   cfg.KMS.VaultKeyName,
		VaultKeyPath:   cfg.KMS.VaultKeyPath,
		VaultNamespace: cfg.KMS.VaultNamespace,
		VaultRoleID:    cfg.KMS.VaultRoleID,
		VaultSecretID:  cfg.KMS.VaultSecretID,
	}

	signer, err := kms.NewSigner(kmsConfig)
	if err != nil {
		log.Error("Failed to initialize KMS signer", zap.Error(err))
		os.Exit(1)
	}
	defer func() { _ = signer.Close() }()

	svc, err := auth.NewService(auth.Config{
		DirectoryServiceURL: directoryServiceURL,
		ServiceAuthToken:    serviceToken,
		ServiceAuthHeader:   serviceHeader,
		ClientStore:         clientStore,
		SAMLStore:           samlStore,
		DeviceStore:         deviceStore,
		SignalStore:         signalStore,
		WebAuthnStore:       webauthnStore,
		BrandingStore:       brandingStore,
		BaseURL:             authServiceURL,
		Signer:              signer,
		// Use SQL stores for persistence
		CodeStore:        codeStore,
		RefreshStore:     refreshStore,
		RevocationStore:  revocationStore,
		TOTPStore:        totpStore,
		SSOProviderStore: ssoProviderStore,
	})
	if err != nil {
		log.Error("Failed to create auth service", zap.Error(err))
		os.Exit(1)
	}

	router := gin.Default()

	// CORS configuration
	if len(cfg.Governance.CORSAllowedOrigins) > 0 {
		origins := cfg.Governance.CORSAllowedOrigins
		router.Use(func(c *gin.Context) {
			origin := c.Request.Header.Get("Origin")
			for _, allowed := range origins {
				if strings.TrimSpace(allowed) == origin {
					c.Header("Access-Control-Allow-Origin", origin)
					c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
					c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Tenant-ID, X-Device-ID, X-OS-Version")
					c.Header("Access-Control-Allow-Credentials", "true")
					break
				}
			}
			if c.Request.Method == "OPTIONS" {
				c.AbortWithStatus(204)
				return
			}
			c.Next()
		})
	}

	// Initialize OpenTelemetry tracing
	shutdownTracer, err := observability.InitTracer(context.Background(), observability.TracerConfig{
		ServiceName:    cfg.Observability.ServiceName,
		ServiceVersion: cfg.Observability.ServiceVersion,
		Environment:    string(cfg.Environment),
	}, log)
	if err != nil {
		log.Error("Failed to initialize tracer", zap.Error(err))
	}
	defer func() { _ = shutdownTracer(context.Background()) }()

	// Initialize and apply observability middleware
	metrics := observability.NewMetrics()
	router.Use(otelgin.Middleware("authsvc"))
	router.Use(observability.PrometheusMiddleware(metrics))
	router.Use(logger.RequestLogger(log))

	// Security Middleware
	router.Use(middleware.SecurityHeadersMiddleware())
	// Rate limit: 20 requests/second, burst of 40
	router.Use(middleware.RateLimitMiddleware(rate.Limit(20), 40))

	// Initialize login attempt store for brute-force protection
	loginAttemptStore := auth.NewLoginAttemptStore(db)

	authHandlers := auth.NewHTTPHandler(svc, log, loginAttemptStore)
	authHandlers.RegisterRoutes(router)
	authHandlers.RegisterBrandingRoutes(router.Group("/"))

	// Register Prometheus metrics handler
	router.GET("/metrics", gin.WrapH(observability.PrometheusHandler()))

	// SAML Setup

	// Register SAML management API
	samlHandlers := saml.NewHTTPHandler(samlStore, log)
	samlHandlers.RegisterRoutes(router.Group("/api/v1"))

	// Developer Portal API (self-service app registration, API keys)
	developerHandlers := auth.NewDeveloperAPIHandler(db, log)
	developerHandlers.RegisterRoutes(router.Group("/api/v1"))

	// Register IdP-initiated endpoint logic is handled inside authHandlers.RegisterRoutes -> svc.SAML()

	log.Info("Auth service starting", zap.String("addr", ":8080"))
	if err := router.Run(":8080"); err != nil {
		log.Error("Auth service failed", zap.Error(err))
		os.Exit(1)
	}
}
