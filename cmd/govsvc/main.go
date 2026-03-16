package main

import (
	"context"
	"os"
	"time"

	"github.com/dhawalhost/wardseal/internal/audit"
	"github.com/dhawalhost/wardseal/internal/connector"
	"github.com/dhawalhost/wardseal/internal/connector/azuread"
	"github.com/dhawalhost/wardseal/internal/connector/google"
	"github.com/dhawalhost/wardseal/internal/connector/ldap"
	"github.com/dhawalhost/wardseal/internal/connector/scim"
	"github.com/dhawalhost/wardseal/internal/governance"
	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/policy"
	"github.com/dhawalhost/wardseal/internal/rbac"
	"github.com/dhawalhost/wardseal/internal/sso"
	"github.com/dhawalhost/wardseal/internal/webhook"
	"github.com/dhawalhost/wardseal/pkg/config"
	"github.com/dhawalhost/wardseal/pkg/database"
	"github.com/dhawalhost/wardseal/pkg/logger"
	"github.com/dhawalhost/wardseal/pkg/middleware"
	"github.com/dhawalhost/wardseal/pkg/observability"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"
)

func main() {
	log := logger.NewFromEnv()
	defer func() { _ = log.Sync() }()

	// Load centralized configuration
	cfg := config.MustLoad()

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
	clientRepo := oauthclient.NewRepository(db)
	reqStore := governance.NewStore(db)

	dirSvcURL := cfg.Governance.DirectoryServiceURL
	dirClient := governance.NewDirectoryClient(dirSvcURL)

	policyEngine := policy.NewSimpleEngine()
	svc := governance.NewService(clientRepo, reqStore, dirClient, policyEngine)

	// Initialize metrics
	metrics := observability.NewMetrics()

	router := gin.Default()

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

	// Add observability middleware
	router.Use(otelgin.Middleware("govsvc"))
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
		KeyPrefix:   cfg.Auth.RateLimitKeyPrefix + ":govsvc",
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

	corsConfig := cors.Config{
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "X-Tenant-ID", "X-User-ID", "X-Device-ID", "X-OS-Version", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}

	origins := cfg.Governance.CORSAllowedOrigins
	if len(origins) == 0 {
		origins = []string{"http://localhost:5173", "http://127.0.0.1:5173"}
	}

	if allowsAllOrigins(origins) {
		corsConfig.AllowAllOrigins = true
	} else {
		corsConfig.AllowOrigins = origins
	}
	router.Use(cors.New(corsConfig))

	// Add metrics endpoint
	router.GET("/metrics", gin.WrapH(observability.PrometheusHandler()))

	govHandlers := governance.NewHTTPHandler(svc, log)
	govHandlers.RegisterRoutes(router)

	// Campaign handlers
	campaignStore := governance.NewCampaignStore(db)
	campaignSvc := governance.NewCampaignService(campaignStore, dirClient)
	campaignHandlers := governance.NewCampaignHTTPHandler(campaignSvc, log)

	apiGroup := router.Group("/api/v1")
	apiGroup.Use(middleware.TenantExtractor(middleware.TenantConfig{
		SlugResolver: func(_ context.Context, tenant string) (string, error) {
			// In local/dev, we allow slugs like 'admin-system' directly
			return tenant, nil
		},
	}))
	campaignHandlers.RegisterRoutes(apiGroup)

	// RBAC handlers
	rbacStore := rbac.NewStore(db)
	rbacSvc := rbac.NewService(rbacStore)
	rbacHandlers := rbac.NewHTTPHandler(rbacSvc, log)
	rbacHandlers.RegisterRoutes(apiGroup)

	// Audit handlers
	auditStore := audit.NewStore(db)
	auditSvc := audit.NewService(auditStore)
	auditHandlers := audit.NewHTTPHandler(auditSvc, log)
	auditHandlers.RegisterRoutes(apiGroup)

	// Organization handlers
	orgStore := governance.NewOrganizationStore(db)
	orgHandlers := governance.NewOrganizationHandler(orgStore, log)
	orgHandlers.RegisterRoutes(apiGroup)

	// Domain verification handlers
	domainVerifyHandler := governance.NewDomainVerificationHandler(db, orgStore, log)
	domainVerifyHandler.RegisterRoutes(apiGroup)

	// SSO handlers
	ssoStore := sso.NewStore(db)
	ssoSvc := sso.NewService(ssoStore)
	ssoHandlers := sso.NewHTTPHandler(ssoSvc, log)
	ssoHandlers.RegisterRoutes(apiGroup)

	// Connector Framework
	connRegistry := connector.NewRegistry()
	connRegistry.Register("scim", scim.New)
	connRegistry.Register("ldap", ldap.New)
	connRegistry.Register("azure-ad", azuread.New)
	connRegistry.Register("google", google.New)

	connStore := connector.NewStore(db)
	connSvc := connector.NewService(connStore, connRegistry)
	connHandlers := connector.NewHTTPHandler(connSvc, log)
	connHandlers.RegisterRoutes(apiGroup)

	// Webhooks
	webhookSvc := webhook.NewService(db)
	webhookHandlers := governance.NewWebhookHTTPHandler(webhookSvc, log)
	webhookHandlers.RegisterRoutes(apiGroup)

	// Initialize active connectors from DB
	// In a real app, this should be done more robustly
	// ctx := context.Background()
	// configs, _ := connStore.List(ctx, "") // Empty tenant ID for all? No, we need per tenant.
	// For now, let's skip auto-loading on startup as we don't have multi-tenant iteration logic here easily.
	// We rely on "lazy" loading or manual toggle in UI for this MVP.

	log.Info("Governance service starting", zap.String("addr", ":8082"))
	if err := router.Run(":8082"); err != nil {
		log.Error("Governance service failed", zap.Error(err))
		os.Exit(1)
	}
}

func allowsAllOrigins(origins []string) bool {
	for _, origin := range origins {
		if origin == "*" {
			return true
		}
	}
	return false
}
