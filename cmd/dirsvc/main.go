package main

import (
	"os"

	"github.com/dhawalhost/velverify/internal/directory"
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

	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "localhost"
	}

	// Database connection
	dbConfig := database.Config{
		Host:     dbHost,
		Port:     5432,
		User:     "user",
		Password: "password",
		DBName:   "identity_platform",
		SSLMode:  "disable",
	}

	db, err := database.NewConnection(dbConfig)
	if err != nil {
		log.Error("Failed to connect to database", zap.Error(err))
		os.Exit(1)
	}

	svc := directory.NewService(db)

	serviceToken := os.Getenv("SERVICE_AUTH_TOKEN")
	if serviceToken == "" {
		serviceToken = "dev-internal-token"
		log.Warn("SERVICE_AUTH_TOKEN not set, using development default")
	}
	serviceHeader := os.Getenv("SERVICE_AUTH_HEADER")

	router := gin.Default()

	// Initialize and apply Prometheus middleware
	metrics := observability.NewMetrics()
	router.Use(observability.PrometheusMiddleware(metrics))

	// Register Prometheus metrics handler
	router.GET("/metrics", gin.WrapH(observability.PrometheusHandler()))

	// Register service routes
	api := directory.NewHTTPHandler(svc, log, directory.HTTPHandlerConfig{
		ServiceAuthToken:  serviceToken,
		ServiceAuthHeader: serviceHeader,
	})
	api.RegisterRoutes(router)

	log.Info("HTTP server starting", zap.String("addr", ":8081"))
	if err := router.Run(":8081"); err != nil {
		log.Error("HTTP server failed", zap.Error(err))
		os.Exit(1)
	}
}
