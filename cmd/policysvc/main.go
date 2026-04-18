package main

import (
	"fmt"
	"os"

	"github.com/dhawalhost/wardseal/internal/policy"
	"github.com/dhawalhost/wardseal/pkg/config"
	"github.com/dhawalhost/wardseal/pkg/database"
	"github.com/dhawalhost/gokit/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func main() {
	// 1. Load configuration
	cfg := config.MustLoad()

	// 2. Initialize logger
	log, err := logger.New(cfg.Observability.LogLevel, cfg.Environment == config.Development)
	if err != nil {
		fmt.Printf("Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Sync() }()

	// 3. Database connection
	dbConfig := database.Config{
		Host:     cfg.Database.Host,
		Port:     cfg.Database.Port,
		User:     cfg.Database.User,
		Password: cfg.Database.Password.Raw(),
		DBName:   cfg.Database.Name,
		SSLMode:  cfg.Database.SSLMode,
	}

	db, err := database.NewConnection(dbConfig)
	if err != nil {
		log.Error("Failed to connect to database", zap.Error(err))
		os.Exit(1)
	}

	// 4. Initialize Policy Stack
	repo := policy.NewRepository(db)
	engine := policy.NewSimpleEngine(repo)
	svc := policy.NewService(repo, engine)

	// 5. Setup Router
	router := gin.Default()
	policyHandlers := policy.NewHTTPHandler(svc, log)
	policyHandlers.RegisterRoutes(router)

	log.Info("Policy service starting", zap.String("addr", ":8083"))
	if err := router.Run(":8083"); err != nil {
		log.Error("Policy service failed", zap.Error(err))
		os.Exit(1)
	}
}
