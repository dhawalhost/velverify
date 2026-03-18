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
	"github.com/go-redis/redis/v8"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"
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
	deviceStore := auth.NewDeviceRepository(db)
	signalStore := auth.NewSignalRepository(db)
	webauthnStore := auth.NewWebAuthnRepository(db)
	brandingStore := auth.NewBrandingRepository(db)
	ssoProviderStore := auth.NewSSOProviderRepository(db)
	tenantStore := auth.NewTenantRepository(db)
	federationStore := auth.NewFederationRepository(db)

	authServiceURL := cfg.Auth.BaseURL

	// Initialize persistent repositories for production durability
	codeStore := auth.NewAuthorizationCodeRepository(db)
	refreshStore := auth.NewRefreshTokenRepository(db)
	revocationStore := auth.NewRevocationRepository(db)
	totpStore := auth.NewTOTPRepository(db)
	appStore := auth.NewDeveloperAppRepository(db)

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
		FederationStore:     federationStore,
		BaseURL:             authServiceURL,
		Signer:              signer,
		// Use SQL stores for persistence
		CodeStore:        codeStore,
		RefreshStore:     refreshStore,
		RevocationStore:  revocationStore,
		TOTPStore:        totpStore,
		SSOProviderStore: ssoProviderStore,
		TenantStore:      tenantStore,
		AppStore:         appStore,
		UIURL:            cfg.Auth.UIURL,
		DeploymentMode:   cfg.Auth.DeploymentMode,
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
					c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Tenant-ID, X-User-ID, X-Device-ID, X-OS-Version")
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

	var rateLimitRedisClient *redis.Client
	if cfg.Auth.RedisAddr != "" {
		rateLimitRedisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Auth.RedisAddr,
			Password: cfg.Auth.RedisPassword,
			DB:       cfg.Auth.RedisDB,
		})
		if err := rateLimitRedisClient.Ping(context.Background()).Err(); err != nil {
			log.Warn("Distributed limiter Redis unavailable; will use strict degraded fallback",
				zap.Error(err),
				zap.String("redis_addr", cfg.Auth.RedisAddr))
			rateLimitRedisClient = nil
		}
	}

	router.Use(middleware.DistributedRateLimitMiddleware(middleware.DistributedRateLimitConfig{
		RedisClient: rateLimitRedisClient,
		KeyPrefix:   cfg.Auth.RateLimitKeyPrefix,
		UseTenant:   cfg.Auth.RateLimitUseTenant,
		DefaultProfile: middleware.RateLimitWindowProfile{
			Requests: cfg.Auth.RateLimitDefault.Requests,
			Window:   cfg.Auth.RateLimitDefault.Window,
		},
		EndpointProfiles: map[string]middleware.RateLimitWindowProfile{
			"login": {
				Requests: cfg.Auth.RateLimitLogin.Requests,
				Window:   cfg.Auth.RateLimitLogin.Window,
			},
			"token": {
				Requests: cfg.Auth.RateLimitToken.Requests,
				Window:   cfg.Auth.RateLimitToken.Window,
			},
			"setup": {
				Requests: cfg.Auth.RateLimitSetup.Requests,
				Window:   cfg.Auth.RateLimitSetup.Window,
			},
			"webhook": {
				Requests: cfg.Auth.RateLimitWebhook.Requests,
				Window:   cfg.Auth.RateLimitWebhook.Window,
			},
		},
		DegradedProfile: middleware.RateLimitWindowProfile{
			Requests: cfg.Auth.RateLimitDegraded.Requests,
			Window:   cfg.Auth.RateLimitDegraded.Window,
		},
	}))

	// API Logger Middleware
	router.Use(middleware.APILogger(db, log))

	// Initialize login attempt repository for brute-force protection
	loginAttemptStore := auth.NewLoginAttemptRepository(db)

	authHandlers := auth.NewHTTPHandler(svc, log, loginAttemptStore, appStore)
	if cfg.Auth.RedisAddr != "" {
		webAuthnSessionStore, err := auth.NewRedisWebAuthnSessionRepository(auth.RedisWebAuthnSessionStoreConfig{
			Addr:      cfg.Auth.RedisAddr,
			Password:  cfg.Auth.RedisPassword,
			DB:        cfg.Auth.RedisDB,
			TTL:       cfg.Auth.WebAuthnSessionTTL,
			KeyPrefix: "authsvc:webauthn:session:",
		})
		if err != nil {
			if cfg.Environment == config.Production {
				log.Fatal("Failed to initialize Redis WebAuthn session store in production",
					zap.Error(err),
					zap.String("redis_addr", cfg.Auth.RedisAddr))
			}
			log.Warn("Failed to initialize Redis WebAuthn session store; using in-memory fallback",
				zap.Error(err),
				zap.String("redis_addr", cfg.Auth.RedisAddr))
		} else {
			authHandlers.SetWebAuthnSessionRepository(webAuthnSessionStore)
			log.Info("Using Redis-backed WebAuthn session repository",
				zap.String("redis_addr", cfg.Auth.RedisAddr),
				zap.Duration("session_ttl", cfg.Auth.WebAuthnSessionTTL))
		}
	} else {
		if cfg.Environment == config.Production {
			log.Fatal("REDIS_ADDR is required in production for WebAuthn session storage")
		}
		log.Warn("REDIS_ADDR not set; using in-memory WebAuthn session repository (not suitable for multi-replica authsvc)")
	}
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
