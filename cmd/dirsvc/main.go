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

	"github.com/dhawalhost/wardseal/internal/directory"
	"github.com/dhawalhost/wardseal/internal/scim"
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

	// Database connection
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

	var bus eventbus.EventBus
	if cfg.Auth.RedisAddr != "" {
		redisClient := redis.NewClient(&redis.Options{
			Addr:     cfg.Auth.RedisAddr,
			Password: cfg.Auth.RedisPassword.Raw(),
			DB:       cfg.Auth.RedisDB,
		})
		if err := redisClient.Ping(context.Background()).Err(); err != nil {
			log.Warn("Redis unavailable for eventbus; events will be dropped", zap.Error(err))
		} else {
			bus = redisbus.NewRedisEventBus(redisClient, log)
		}
	} else {
		log.Warn("No Redis configured; eventbus disabled")
	}

	repo := directory.NewRepository(db)
	svc := directory.NewService(repo, bus)

	serviceToken := cfg.Directory.ServiceAuthToken
	if serviceToken.IsEmpty() {
		serviceToken = "dev-internal-token" //nolint:gosec // G101: dev-only fallback, not production credentials
		log.Warn("SERVICE_AUTH_TOKEN not set, using development default")
	}
	serviceHeader := cfg.Directory.ServiceAuthHeader

	router := gin.Default()

	// CORS configuration
	if len(cfg.Governance.CORSAllowedOrigins) > 0 {
		origins := cfg.Governance.CORSAllowedOrigins
		router.Use(func(c *gin.Context) {
			origin := c.Request.Header.Get("Origin")
			for _, allowed := range origins {
				if strings.TrimSpace(allowed) == origin {
					c.Header("Access-Control-Allow-Origin", origin)
					c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
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
	router.Use(otelgin.Middleware("dirsvc"))
	router.Use(wardsealobs.PrometheusMiddleware(metrics))
	router.Use(middleware.Wrap(gokitmiddleware.RequestID())) // Inject tracing ID
	router.Use(middleware.APILogger(nil, log))

	// Security Middleware
	router.Use(middleware.Wrap(gokitmiddleware.SecureHeaders()))

	var rateLimitRedisClient *redis.Client
	if cfg.Auth.RedisAddr != "" {
		rateLimitRedisClient = redis.NewClient(&redis.Options{
			Addr:     cfg.Auth.RedisAddr,
			Password: cfg.Auth.RedisPassword.Raw(),
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
		KeyPrefix:   cfg.Auth.RateLimitKeyPrefix + ":dirsvc",
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

	// Register Prometheus metrics handler
	router.GET("/metrics", gin.WrapH(wardsealobs.PrometheusHandler()))

	// Register standardized health checks
	healthHandler := health.NewHandler()
	router.GET("/healthz", gin.WrapF(healthHandler.LiveHandler()))
	router.GET("/readyz", gin.WrapF(healthHandler.ReadyHandler()))

	// Register service routes
	api := directory.NewHTTPHandler(svc, log, directory.HTTPHandlerConfig{
		ServiceAuthToken:  serviceToken.Raw(),
		ServiceAuthHeader: serviceHeader,
	})
	api.RegisterRoutes(router)

	// Register SCIM routes
	scimSvc := scim.NewService(svc)
	scimHandlers := scim.NewHTTPHandler(scimSvc, repo, serviceToken.Raw(), log)
	scimHandlers.RegisterRoutes(router)

	// Server Configuration with Graceful Shutdown
	srv := &http.Server{
		Addr:         ":8081",
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	go func() {
		log.Info("Directory service starting", zap.String("addr", ":8081"))
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Error("Directory service failed", zap.Error(err))
			os.Exit(1)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Info("Shutting down directory service...")

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Error("Directory service forced to shutdown", zap.Error(err))
	}
	log.Info("Directory service exited gracefully")
}
