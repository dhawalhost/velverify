package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
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
	"github.com/dhawalhost/wardseal/internal/chatops"
	"github.com/dhawalhost/wardseal/internal/discovery"
	"github.com/dhawalhost/wardseal/pkg/kms"
	"github.com/dhawalhost/wardseal/pkg/config"
	"github.com/dhawalhost/wardseal/pkg/database"
	"github.com/dhawalhost/wardseal/pkg/middleware"
	wardsealobs "github.com/dhawalhost/wardseal/pkg/observability"
	gokitconfig "github.com/dhawalhost/gokit/config"
	"github.com/dhawalhost/gokit/health"
	"github.com/dhawalhost/gokit/logger"
	gokitmiddleware "github.com/dhawalhost/gokit/middleware"
	"github.com/dhawalhost/gokit/observability"
	"github.com/dhawalhost/wardseal/pkg/eventbus"
	"github.com/dhawalhost/wardseal/pkg/eventbus/redisbus"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"go.opentelemetry.io/contrib/instrumentation/github.com/gin-gonic/gin/otelgin"
	"go.uber.org/zap"
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
	clientRepo := oauthclient.NewRepository(db)
	reqRepo := governance.NewRepository(db)
	orgRepo := governance.NewOrganizationRepository(db)

	dirSvcURL := cfg.Governance.DirectoryServiceURL
	dirClient := governance.NewDirectoryClient(dirSvcURL, cfg.Directory.ServiceAuthHeader, cfg.Directory.ServiceAuthToken.Raw())

	policyRepo := policy.NewRepository(db)
	policyEngine := policy.NewSimpleEngine(policyRepo)
	
	// Initialize metrics
	metrics := wardsealobs.NewMetrics()

	var redisClient *redis.Client
	var bus eventbus.EventBus
	if cfg.Auth.RedisAddr != "" {
		redisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Auth.RedisAddr,
			Password: cfg.Auth.RedisPassword.Raw(),
			DB:       cfg.Auth.RedisDB,
		})
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			log.Warn("Redis unavailable for eventbus; events will be dropped", zap.Error(err))
			redisClient = nil
		} else {
			bus = redisbus.NewRedisEventBus(redisClient, log)
		}
	}

	rbacRepo := rbac.NewRepository(db)
	rbacSvc := rbac.NewService(rbacRepo)
	endpointRepo := governance.NewEndpointRepository(db)

	// PROPER ENCRYPTION: Initialize KMS Cipher for per-tenant secret protection
	kmsCfg := kms.Config{
		Provider:       cfg.KMS.Provider,
		PrivateKeyPath: cfg.KMS.PrivateKeyPath,
		PublicKeyPath:  cfg.KMS.PublicKeyPath,
		MasterKey:      cfg.KMS.MasterKey,
		VaultAddr:      cfg.KMS.VaultAddr,
		VaultToken:     cfg.KMS.VaultToken,
		VaultKeyName:   cfg.KMS.VaultKeyName,
		VaultKeyPath:   cfg.KMS.VaultKeyPath,
		VaultNamespace: cfg.KMS.VaultNamespace,
		VaultRoleID:    cfg.KMS.VaultRoleID,
		VaultSecretID:  cfg.KMS.VaultSecretID,
	}

	cipher, err := kms.NewCipher(kmsCfg)
	if err != nil {
		log.Fatal("Failed to initialize KMS Cipher", zap.Error(err))
	}

	// Dynamic ChatOps Repository
	chatOpsRepo := chatops.NewRepository(db, cipher)
	chatOpsHandlers := chatops.NewHTTPHandler(chatOpsRepo, log)

	svc := governance.NewService(clientRepo, reqRepo, orgRepo, endpointRepo, dirClient, policyEngine, rbacSvc, bus)

	router := gin.Default()

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

	// Add observability middleware
	router.Use(otelgin.Middleware("govsvc"))
	router.Use(wardsealobs.PrometheusMiddleware(metrics))
	router.Use(middleware.Wrap(gokitmiddleware.RequestID())) // Inject tracing ID
	router.Use(middleware.APILogger(nil, log))

	// Security Middleware
	router.Use(middleware.Wrap(gokitmiddleware.SecureHeaders()))

	var rateLimitRedisClient *redis.Client
	if redisClient != nil {
		rateLimitRedisClient = redisClient
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
	router.GET("/metrics", gin.WrapH(wardsealobs.PrometheusHandler()))

	// Register standardized health checks
	healthHandler := health.NewHandler()
	router.GET("/healthz", gin.WrapF(healthHandler.LiveHandler()))
	router.GET("/readyz", gin.WrapF(healthHandler.ReadyHandler()))

	campaignRepo := governance.NewCampaignRepository(db)
	campaignSvc := governance.NewCampaignService(campaignRepo, dirClient, bus)
	campaignSvc.SetGovernanceService(svc) // Link services
	webhookSvc := webhook.NewService(db)

	govHandlers := governance.NewHTTPHandler(svc, campaignSvc, webhookSvc, log)
	govHandlers.RegisterRoutes(router)

	apiGroup := router.Group("/api/v1")
	apiGroup.Use(middleware.TenantExtractor(middleware.TenantConfig{
		SlugResolver: dirClient.ResolveTenantSlug,
	}))

	// apiGroup is already handled above the RBAC and Audit handlers
	rbacHandlers := rbac.NewHTTPHandler(rbacSvc, log)
	rbacHandlers.RegisterRoutes(apiGroup)

	// Audit handlers
	auditRepo := audit.NewRepository(db)
	auditSvc := audit.NewService(auditRepo)
	auditHandlers := audit.NewHTTPHandler(auditSvc, log)
	auditHandlers.RegisterRoutes(apiGroup)

	// Automatic Audit Hub: captures all EventBus activity
	if bus != nil {
		auditSub := audit.NewAuditSubscriber(auditSvc, bus, log)
		if err := auditSub.RegisterSubscribers(context.Background()); err != nil {
			log.Error("Failed to register audit subscribers", zap.Error(err))
		} else {
			log.Info("Audit EventBus integration active")
		}
	}

	// Domain verification handlers
	domainVerifyHandler := governance.NewDomainVerificationHandler(db, orgRepo, log)
	domainVerifyHandler.RegisterRoutes(apiGroup)

	// SSO handlers
	ssoRepo := sso.NewRepository(db)
	ssoSvc := sso.NewService(ssoRepo)
	ssoHandlers := sso.NewHTTPHandler(ssoSvc, log)
	ssoHandlers.RegisterRoutes(apiGroup)

	// Connector Framework
	connRegistry := connector.NewRegistry()
	connRegistry.Register("scim", scim.New)
	connRegistry.Register("ldap", ldap.New)
	connRegistry.Register("azure-ad", azuread.New)
	connRegistry.Register("google", google.New)

	connRepo := connector.NewRepository(db, cipher)
	connSvc := connector.NewService(connRepo, connRegistry)
	connHandlers := connector.NewHTTPHandler(connSvc, log)
	connHandlers.RegisterRoutes(apiGroup)

	// Resource Discovery Framework
	discoveryRepo := discovery.NewRepository(db)
	discoveryJobStore := discovery.NewRedisJobStore(redisClient)

	discoverySvc := discovery.NewService(discoveryRepo, discoveryJobStore, connRegistry, bus, log)
	discoveryHandlers := discovery.NewHTTPHandler(discoverySvc, discoveryRepo, discoveryJobStore, bus, log)
	discoveryHandlers.RegisterRoutes(apiGroup)

	// Start Discovery Worker
	discoverySvc.Start(context.Background())

	// Slack ChatOps integration (Dynamic/Multi-tenant)
	slackHandler := chatops.NewSlackHandler(svc, dirClient, chatOpsRepo, cfg.Auth.UIURL, string(cfg.Environment), log)
	
	// Dashboard Management API
	chatOpsHandlers.RegisterRoutes(apiGroup)

	// ChatOps Automatic safety loop
	if bus != nil {
		chatOpsSub := chatops.NewChatOpsSubscriber(slackHandler, bus, log)
		if err := chatOpsSub.RegisterSubscribers(context.Background()); err != nil {
			log.Error("Failed to register ChatOps subscribers", zap.Error(err))
		} else {
			log.Info("ChatOps safety confirmation loops active")
		}
	}

	// Slack Callback Handlers (Publicly accessible but verified via signing secret)
	slackRoutes := router.Group("/integrations/slack")
	{
		slackRoutes.POST("/commands", gin.WrapF(slackHandler.HandleCommand))
		slackRoutes.POST("/interactions", gin.WrapF(slackHandler.HandleInteraction))
	}

	// Initialize active connectors from DB
	// In a real app, this should be done more robustly
	// ctx := context.Background()
	// configs, _ := connStore.List(ctx, "") // Empty tenant ID for all? No, we need per tenant.
	// For now, let's skip auto-loading on startup as we don't have multi-tenant iteration logic here easily.
	// We rely on "lazy" loading or manual toggle in UI for this MVP.

	// Server Configuration with Graceful Shutdown
	srv := &http.Server{
		Addr:         ":8082",
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	// Compliance Background Worker (Recertification)
	go func() {
		ticker := time.NewTicker(24 * time.Hour) // Run daily sweep
		defer ticker.Stop()
		
		log.Info("Compliance recertification worker started")
		for {
			select {
			case <-ticker.C:
				log.Info("Running daily compliance recertification sweep...")
				ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
				err := campaignSvc.GenerateRecertificationCampaign(ctx, "default", fmt.Sprintf("Quarterly Review - %s", time.Now().Format("2006-Q1")))
				if err != nil {
					log.Error("Failed to generate auto-campaign", zap.Error(err))
				}
				cancel()
			case <-quit:
				return
			}
		}
	}()

	// JIT Temporal Access Sweeper
	go func() {
		ticker := time.NewTicker(1 * time.Minute) // Check every minute
		defer ticker.Stop()

		log.Info("JIT temporal access sweeper started")
		for {
			select {
			case <-ticker.C:
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				expired, err := rbacSvc.ListExpiredAssignments(ctx)
				if err != nil {
					log.Error("Failed to list expired assignments", zap.Error(err))
				} else if len(expired) > 0 {
					log.Info("Purging expired temporal assignments", zap.Int("count", len(expired)))
					for _, asg := range expired {
						err := rbacSvc.RemoveRoleFromUser(ctx, asg.UserID, asg.RoleID)
						if err != nil {
							log.Error("Failed to revoke expired role", 
								zap.String("user_id", asg.UserID), 
								zap.String("role_id", asg.RoleID), 
								zap.Error(err))
						} else {
							log.Info("Successfully revoked expired JIT role", 
								zap.String("user_id", asg.UserID), 
								zap.String("role_id", asg.RoleID))
						}
					}
				}
				cancel()
			case <-quit:
				return
			}
		}
	}()

	go func() {
		log.Info("Governance service starting", zap.String("addr", ":8082"))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Governance service failed", zap.Error(err))
			os.Exit(1)
		}
	}()

	<-quit
	log.Info("Shutting down governance service...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("Governance service forced to shutdown", zap.Error(err))
	}
	log.Info("Governance service exited gracefully")
}

func allowsAllOrigins(origins []string) bool {
	for _, origin := range origins {
		if origin == "*" {
			return true
		}
	}
	return false
}
