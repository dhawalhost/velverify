package main

import (
	"context"
	"os"
	"strings"

	"github.com/dhawalhost/wardseal/internal/directory"
	"github.com/dhawalhost/wardseal/internal/scim"
	"github.com/dhawalhost/wardseal/pkg/config"
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

	// Load centralized configuration
	cfg := config.MustLoad()

	// Database connection
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

	svc := directory.NewService(db)

	serviceToken := cfg.Directory.ServiceAuthToken
	if serviceToken == "" {
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
					c.Header("Access-Control-Allow-Headers", "Origin, Content-Type, Authorization, X-Tenant-ID")
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
	router.Use(otelgin.Middleware("dirsvc"))
	router.Use(observability.PrometheusMiddleware(metrics))
	router.Use(observability.PrometheusMiddleware(metrics))
	router.Use(logger.RequestLogger(log))

	// Security Middleware
	router.Use(middleware.SecurityHeadersMiddleware())
	// Rate limit: 20 req/s, burst 40
	router.Use(middleware.RateLimitMiddleware(rate.Limit(20), 40))

	// Security Middleware
	router.Use(middleware.SecurityHeadersMiddleware())
	// Rate limit: 20 req/s, burst 40 (adjust as needed for bulk SCIM ops)
	router.Use(middleware.RateLimitMiddleware(rate.Limit(20), 40))

	// Register Prometheus metrics handler
	router.GET("/metrics", gin.WrapH(observability.PrometheusHandler()))

	// Register service routes
	api := directory.NewHTTPHandler(svc, log, directory.HTTPHandlerConfig{
		ServiceAuthToken:  serviceToken,
		ServiceAuthHeader: serviceHeader,
	})
	api.RegisterRoutes(router)

	// Register SCIM routes
	scimSvc := scim.NewService(svc)
	scimHandlers := scim.NewHTTPHandler(scimSvc, log)
	scimHandlers.RegisterRoutes(router)

	log.Info("HTTP server starting", zap.String("addr", ":8081"))
	if err := router.Run(":8081"); err != nil {
		log.Error("HTTP server failed", zap.Error(err))
		os.Exit(1)
	}
}
