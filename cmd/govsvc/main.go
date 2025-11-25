package main

import (
	"os"

	"github.com/dhawalhost/velverify/internal/governance"
	"github.com/dhawalhost/velverify/internal/oauthclients"
	"github.com/dhawalhost/velverify/pkg/database"
	"github.com/dhawalhost/velverify/pkg/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func main() {
	log := logger.New(zapcore.DebugLevel)
	defer log.Sync()

	dbHost := envOr("DB_HOST", "localhost")
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
	clientRepo := oauthclients.NewRepository(db)

	svc := governance.NewService(clientRepo)

	router := gin.Default()
	govHandlers := governance.NewHTTPHandler(svc, log)
	govHandlers.RegisterRoutes(router)

	log.Info("Governance service starting", zap.String("addr", ":8082"))
	if err := router.Run(":8082"); err != nil {
		log.Error("Governance service failed", zap.Error(err))
		os.Exit(1)
	}
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
