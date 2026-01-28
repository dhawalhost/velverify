package main

import (
	"context"
	"os"
	"strings"

	"github.com/dhawalhost/wardseal/internal/auth"
	"github.com/dhawalhost/wardseal/internal/license"
	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/saml"
	"github.com/dhawalhost/wardseal/pkg/database"
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

	// Enterprise License Verification
	if os.Getenv("REQUIRE_LICENSE") == "true" {
		log.Info("Checking Enterprise License...")

		pubKeyPath := os.Getenv("LICENSE_PUBLIC_KEY_PATH")
		if pubKeyPath == "" {
			pubKeyPath = "/etc/wardseal/license_public.pem"
		}

		pubKey, err := os.ReadFile(pubKeyPath) //nolint:gosec // G304: path is from trusted env var
		if err != nil {
			log.Fatal("Failed to read license public key", zap.Error(err))
		}

		mgr, err := license.NewManager(pubKey)
		if err != nil {
			log.Fatal("Failed to initialize license manager", zap.Error(err))
		}

		licenseKey := os.Getenv("LICENSE_KEY")
		if licenseKey == "" {
			log.Fatal("LICENSE_KEY environment variable is required for enterprise edition")
		}

		lic, err := mgr.Verify(licenseKey)
		if err != nil {
			log.Fatal("Invalid license key", zap.Error(err))
		}

		log.Info("Enterprise License Verified",
			zap.String("customer", lic.CustomerName),
			zap.Time("expires_at", lic.ExpiresAt),
			zap.String("plan", lic.Plan))
	}

	directoryServiceURL := os.Getenv("DIRECTORY_SERVICE_URL")
	if directoryServiceURL == "" {
		directoryServiceURL = "http://dirsvc:8081" // Use service name in docker-compose
	}

	serviceToken := os.Getenv("SERVICE_AUTH_TOKEN")
	if serviceToken == "" {
		serviceToken = "dev-internal-token" //nolint:gosec // G101: dev-only fallback, not production credentials
		log.Warn("SERVICE_AUTH_TOKEN not set, using development default")
	}
	serviceHeader := os.Getenv("SERVICE_AUTH_HEADER")

	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "localhost"
	}
	dbConfig := database.Config{
		Host:     dbHost,
		Port:     5432,
		User:     envOr("DB_USER", "user"),
		Password: envOr("DB_PASSWORD", "password"),
		DBName:   envOr("DB_NAME", "identity_platform"),
		SSLMode:  envOr("DB_SSLMODE", "disable"),
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

	authServiceURL := os.Getenv("AUTH_SERVICE_URL")
	if authServiceURL == "" {
		authServiceURL = "http://localhost:8080"
	}

	// Initialize persistent stores for production durability
	codeStore := auth.NewSQLAuthorizationCodeStore(db)
	refreshStore := auth.NewSQLRefreshTokenStore(db)
	revocationStore := auth.NewSQLRevocationStore(db)
	totpStore := auth.NewTOTPStore(db)

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
	corsOrigins := os.Getenv("CORS_ALLOWED_ORIGINS")
	if corsOrigins != "" {
		origins := strings.Split(corsOrigins, ",")
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
		ServiceName:    "authsvc",
		ServiceVersion: "1.0.0",
		Environment:    envOr("ENVIRONMENT", "development"),
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

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
