package main

import (
	"os"

	"github.com/dhawalhost/gokit/logger"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"time"

	"github.com/dhawalhost/gokit/health"
	"github.com/dhawalhost/wardseal/internal/provisioning"
	"github.com/dhawalhost/wardseal/pkg/config"
)

func main() {
	// Load centralized configuration
	cfg := config.MustLoad()

	log, err := logger.New(cfg.Observability.LogLevel, cfg.Environment == config.Development)
	if err != nil {
		panic(err)
	}
	defer func() { _ = log.Sync() }()

	svc := provisioning.NewService()

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

	provHandlers := provisioning.NewHTTPHandler(svc, log)
	provHandlers.RegisterRoutes(router)

	// Health check
	healthHandler := health.NewHandler()
	router.GET("/healthz", gin.WrapF(healthHandler.LiveHandler()))
	router.GET("/provisioning/healthz", gin.WrapF(healthHandler.LiveHandler()))

	log.Info("Provisioning service starting", zap.String("addr", ":8084"))
	if err := router.Run(":8084"); err != nil {
		log.Error("Provisioning service failed", zap.Error(err))
		os.Exit(1)
	}
}
