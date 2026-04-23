package main

import (
	"fmt"
	"os"

	"github.com/dhawalhost/gokit/logger"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"time"

	"github.com/dhawalhost/wardseal/internal/policy"
	"github.com/dhawalhost/wardseal/pkg/config"
	"github.com/dhawalhost/wardseal/pkg/database"
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

	// CORS configuration
	origins := cfg.Governance.CORSAllowedOrigins
	if len(origins) == 0 {
		origins = []string{"http://localhost:5173", "http://127.0.0.1:5173"}
	}

	router.Use(cors.New(cors.Config{
		AllowOrigins:     origins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-Tenant-ID", "X-User-ID", "X-Device-ID", "X-OS-Version", "Accept", "X-Requested-With", "Accept-Encoding", "Cache-Control"},
		ExposeHeaders:    []string{"Content-Length", "Access-Control-Allow-Origin"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	policyHandlers := policy.NewHTTPHandler(svc, log)
	policyHandlers.RegisterRoutes(router)

	log.Info("Policy service starting", zap.String("addr", ":8083"))
	if err := router.Run(":8083"); err != nil {
		log.Error("Policy service failed", zap.Error(err))
		os.Exit(1)
	}
}
