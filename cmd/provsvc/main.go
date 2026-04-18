package main

import (
	"os"

	"github.com/dhawalhost/wardseal/internal/provisioning"
	"github.com/dhawalhost/gokit/logger"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func main() {
	log, _ := logger.New("debug", true)
	defer func() { _ = log.Sync() }()

	svc := provisioning.NewService()

	router := gin.Default()
	provHandlers := provisioning.NewHTTPHandler(svc, log)
	provHandlers.RegisterRoutes(router)

	log.Info("Provisioning service starting", zap.String("addr", ":8084"))
	if err := router.Run(":8084"); err != nil {
		log.Error("Provisioning service failed", zap.Error(err))
		os.Exit(1)
	}
}
