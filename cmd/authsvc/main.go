package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	gokitconfig "github.com/dhawalhost/gokit/config"
	"github.com/dhawalhost/gokit/health"
	"github.com/dhawalhost/gokit/logger"
	gokitmiddleware "github.com/dhawalhost/gokit/middleware"
	"github.com/dhawalhost/gokit/observability"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/internal/auth"
	"github.com/dhawalhost/wardseal/internal/authz"
	"github.com/dhawalhost/wardseal/internal/license"
	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/rbac"
	"github.com/dhawalhost/wardseal/internal/saml"
	"github.com/dhawalhost/wardseal/pkg/config"
	"github.com/dhawalhost/wardseal/pkg/database"
	"github.com/dhawalhost/wardseal/pkg/kms"
	"github.com/dhawalhost/wardseal/pkg/middleware"
	wardsealobs "github.com/dhawalhost/wardseal/pkg/observability"
)

func main() {
	// Load centralized configuration
	cfg := config.MustLoad()

	log, err := logger.New(cfg.Observability.LogLevel, cfg.Environment == config.Development)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Sync() }()

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

		lic, err := mgr.Verify(cfg.License.Key.Raw())
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
	if serviceToken.IsEmpty() {
		serviceToken = "dev-internal-token" //nolint:gosec // G101: dev-only fallback, not production credentials
		log.Warn("SERVICE_AUTH_TOKEN not set, using development default")
	}
	serviceHeader := cfg.Auth.ServiceAuthHeader

	dbConfig := database.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password.Raw(), // Securely injected by Vault if configured
		DBName:   cfg.Database.Name,
		SSLMode:  cfg.Database.SSLMode,
	}

	db, err := database.NewConnection(dbConfig)
	if err != nil {
		log.Error("Failed to connect to database", zap.Error(err))
		os.Exit(1)
	}
	clientStore := oauthclient.NewRepository(db)
	samlStore := saml.NewStore(db, cfg.Auth.DirectoryServiceURL, cfg.Auth.ServiceAuthToken.Raw(), cfg.Auth.ServiceAuthHeader)
	deviceStore := auth.NewDeviceRepository(db)
	signalStore := auth.NewSignalRepository(db)
	webauthnStore := auth.NewWebAuthnRepository(db)
	brandingStore := auth.NewBrandingRepository(db)
	ssoProviderStore := auth.NewSSOProviderRepository(db)
	tenantStore := auth.NewTenantRepository(db)
	federationStore := auth.NewFederationRepository(db)
	ipPolicyStore := auth.NewIPPolicyRepository(db)
	rbacRepo := rbac.NewRepository(db)

	// Initialize Redis Client
	var globalRedisClient redis.UniversalClient
	if cfg.Auth.RedisAddr != "" {
		importStrings := func(s string) []string {
			var res []string
			for _, part := range strings.Split(s, ",") {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					res = append(res, trimmed)
				}
			}
			return res
		}

		globalRedisClient = redis.NewUniversalClient(&redis.UniversalOptions{
			Addrs:    importStrings(cfg.Auth.RedisAddr),
			Password: cfg.Auth.RedisPassword.Raw(),
			DB:       cfg.Auth.RedisDB,
		})
		if err := globalRedisClient.Ping(context.Background()).Err(); err != nil {
			log.Warn("Redis unavailable; caches will degrade to in-memory fallbacks",
				zap.Error(err),
				zap.String("redis_addr", cfg.Auth.RedisAddr))
			globalRedisClient = nil
		}
	}

	// Phase 2: The Graph (ReBAC)
	authzRepo := authz.NewRepository(db)
	authzEngine := authz.NewEngine(authzRepo, log, globalRedisClient)
	rbacSvc := rbac.NewService(rbacRepo, authzEngine) 

	authServiceURL := cfg.Auth.BaseURL

	// Initialize persistent repositories for production durability
	codeStore := auth.NewAuthorizationCodeRepository(db)
	refreshStore := auth.NewRefreshTokenRepository(db)
	revocationStore := auth.NewRevocationRepository(db)
	totpStore := auth.NewTOTPRepository(db)
	appStore := auth.NewDeveloperAppRepository(db)
	workloadStore := auth.NewWorkloadRepository(db)
	loginAttemptStore := auth.NewLoginAttemptRepository(db)

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
		MasterKey:      cfg.KMS.MasterKey,
	}

	signer, err := kms.NewSigner(kmsConfig)
	if err != nil {
		log.Error("Failed to initialize KMS signer", zap.Error(err))
		os.Exit(1)
	}
	defer func() { _ = signer.Close() }()

	cipher, err := kms.NewCipher(kmsConfig)
	if err != nil {
		log.Error("Failed to initialize KMS cipher", zap.Error(err))
		os.Exit(1)
	}

	samlIdPRepo := saml.NewIdPRepository(db, cipher)

	svc, err := auth.NewService(auth.Config{
		DirectoryServiceURL: directoryServiceURL,
		ServiceAuthToken:    serviceToken.Raw(),
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
		Cipher:              cipher,
		SAMLIdPRepo:         samlIdPRepo,
		IPPolicyStore:       ipPolicyStore,
		RBACStore:           rbacRepo,
		GraphEngine:         authzEngine,
		RedisClient:         globalRedisClient,
		// Use SQL stores for persistence
		CodeStore:         codeStore,
		RefreshStore:      refreshStore,
		RevocationStore:   revocationStore,
		TOTPStore:         totpStore,
		SSOProviderStore:  ssoProviderStore,
		TenantStore:       tenantStore,
		AppStore:          appStore,
		WorkloadStore:     workloadStore,
		UIURL:             cfg.Auth.UIURL,
		LoginAttemptStore: loginAttemptStore,
		DeploymentMode:    cfg.Auth.DeploymentMode,
		CookieDomain:      cfg.Auth.CookieDomain,
	})
	if err != nil {
		log.Error("Failed to create auth service", zap.Error(err))
		os.Exit(1)
	}

	router := gin.Default()
	// CORS configuration
	origins := cfg.Governance.CORSAllowedOrigins
	if len(origins) == 0 {
		origins = []string{"http://localhost:5173", "http://127.0.0.1:5173"}
	}

	router.Use(cors.New(cors.Config{
		AllowOrigins:     origins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Tenant-ID", "X-User-ID", "X-Device-ID", "X-OS-Version", "X-Tenant-Role", "Accept", "X-Requested-With", "Accept-Encoding", "Cache-Control"},
		ExposeHeaders:    []string{"Content-Length", "Access-Control-Allow-Origin", "X-Service-Auth"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	// Initialize OpenTelemetry tracing
	shutdownTracer, err := observability.InitTracer(context.Background(), gokitconfig.TelemetryConfig{
		Enabled:      cfg.Observability.OTELEndpoint != "",
		OTLPEndpoint: cfg.Observability.OTELEndpoint,
		ServiceName:  cfg.Observability.ServiceName,
	})
	if err != nil {
		log.Error("Failed to initialize tracer", zap.Error(err))
	}
	defer func() { _ = shutdownTracer(context.Background()) }()

	// Initialize and apply observability middleware
	metrics := wardsealobs.NewMetrics()
	router.Use(otelgin.Middleware("authsvc"))
	router.Use(wardsealobs.PrometheusMiddleware(metrics))
	router.Use(middleware.Wrap(gokitmiddleware.RequestID())) // Inject tracing ID

	// Security Middleware
	router.Use(middleware.Wrap(gokitmiddleware.SecureHeaders()))
	router.Use(middleware.SoftwareWAFMiddleware())

	router.Use(middleware.DistributedRateLimitMiddleware(middleware.DistributedRateLimitConfig{
		RedisClient: globalRedisClient,
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

	authHandlers := auth.NewHTTPHandler(svc, log, loginAttemptStore, appStore)
	if cfg.Auth.RedisAddr != "" {
		webAuthnSessionStore, err := auth.NewRedisWebAuthnSessionRepository(auth.RedisWebAuthnSessionStoreConfig{
			Addr:      cfg.Auth.RedisAddr,
			Password:  cfg.Auth.RedisPassword.Raw(),
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

	// Register Prometheus metrics handler
	router.GET("/metrics", gin.WrapH(wardsealobs.PrometheusHandler()))

	// Register standardized health checks
	healthHandler := health.NewHandler()
	router.GET("/healthz", gin.WrapF(healthHandler.LiveHandler()))
	router.GET("/readyz", gin.WrapF(healthHandler.ReadyHandler()))

	// SAML Setup

	// Register SAML management API
	samlHandlers := saml.NewHTTPHandler(samlStore, samlIdPRepo, cipher, log)
	samlHandlers.RegisterRoutes(router.Group("/api/v1"))

	// Developer Portal API (self-service app registration, API keys)
	developerHandlers := auth.NewDeveloperAPIHandler(db, log)
	developerHandlers.RegisterRoutes(router.Group("/api/v1"))

	// RBAC API (Roles and Permissions)
	rbacHandlers := rbac.NewHTTPHandler(rbacSvc, log)
	rbacGroup := router.Group("/api/v1")
	rbacGroup.Use(middleware.TenantExtractor(middleware.TenantConfig{
		HeaderName: "X-Tenant-ID",
		SlugResolver: func(ctx context.Context, slug string) (string, error) {
			return svc.ResolveTenantSlug(ctx, slug)
		},
	}))
	rbacHandlers.RegisterRoutes(rbacGroup)

	// Register IdP-initiated endpoint logic is handled inside authHandlers.RegisterRoutes -> svc.SAML()

	// Server Configuration with Graceful Shutdown
	srv := &http.Server{
		Addr:         ":8080",
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Info("Auth service starting", zap.String("addr", ":8080"))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Auth service failed", zap.Error(err))
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("Shutting down auth service...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("Auth service forced to shutdown", zap.Error(err))
	}
	log.Info("Auth service exited gracefully")
}
