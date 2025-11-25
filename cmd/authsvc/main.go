package main

import (
	"os"

	"github.com/dhawalhost/velverify/internal/auth"
	"github.com/dhawalhost/velverify/internal/oauthclients"
	"github.com/dhawalhost/velverify/pkg/database"
	"github.com/dhawalhost/velverify/pkg/logger"
	"github.com/dhawalhost/velverify/pkg/observability"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	log := logger.New(zapcore.DebugLevel)
	defer log.Sync()

	directoryServiceURL := os.Getenv("DIRECTORY_SERVICE_URL")
	if directoryServiceURL == "" {
		directoryServiceURL = "http://dirsvc:8081" // Use service name in docker-compose
	}

	serviceToken := os.Getenv("SERVICE_AUTH_TOKEN")
	if serviceToken == "" {
		serviceToken = "dev-internal-token"
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
	clientStore := oauthclients.NewRepository(db)

	svc, err := auth.NewService(auth.Config{
		DirectoryServiceURL: directoryServiceURL,
		ServiceAuthToken:    serviceToken,
		ServiceAuthHeader:   serviceHeader,
		ClientStore:         clientStore,
	})
	if err != nil {
		log.Error("Failed to create auth service", zap.Error(err))
		os.Exit(1)
	}

	router := gin.Default()

	// Initialize and apply Prometheus middleware
	metrics := observability.NewMetrics()
	router.Use(observability.PrometheusMiddleware(metrics))

	authHandlers := auth.NewHTTPHandler(svc, log)
	authHandlers.RegisterRoutes(router)

	// Register Prometheus metrics handler
	router.GET("/metrics", gin.WrapH(observability.PrometheusHandler()))

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
