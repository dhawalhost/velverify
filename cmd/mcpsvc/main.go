package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/dhawalhost/gokit/logger"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"

	"github.com/dhawalhost/wardseal/internal/auth"
	"github.com/dhawalhost/wardseal/internal/authz"
	"github.com/dhawalhost/wardseal/internal/governance"
	"github.com/dhawalhost/wardseal/internal/mcp"
	"github.com/dhawalhost/wardseal/internal/oauthclient"
	"github.com/dhawalhost/wardseal/internal/policy"
	"github.com/dhawalhost/wardseal/internal/rbac"
	"github.com/dhawalhost/wardseal/pkg/config"
	"github.com/dhawalhost/wardseal/pkg/database"
)

func main() {
	// Load configuration
	cfg := config.MustLoad()

	// Initialise logger (redirected to stderr because stdout is for MCP)
	log, err := logger.New(cfg.Observability.LogLevel, cfg.Environment == config.Development)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to initialize logger: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = log.Sync() }()

	// Connect to database
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

	// Initialize core repositories required for governance service
	clientRepo := oauthclient.NewRepository(db)
	reqRepo := governance.NewRepository(db)
	orgRepo := governance.NewOrganizationRepository(db)
	endpointRepo := governance.NewEndpointRepository(db)
	workloadRepo := auth.NewWorkloadRepository(db)
	policyRepo := policy.NewRepository(db)
	policyEngine := policy.NewSimpleEngine(policyRepo)

	dirClient := governance.NewDirectoryClient(
		cfg.Governance.DirectoryServiceURL,
		cfg.Directory.ServiceAuthHeader,
		cfg.Directory.ServiceAuthToken.Raw(),
	)

	rbacRepo := rbac.NewRepository(db)
	authzRepo := authz.NewRepository(db)
	authzEngine := authz.NewEngine(authzRepo, log)
	rbacSvc := rbac.NewService(rbacRepo, authzEngine)

	// Initialize Governance Service
	govSvc := governance.NewService(
		clientRepo, reqRepo, orgRepo, endpointRepo, workloadRepo,
		dirClient, policyEngine, rbacSvc, authzEngine, nil, // No event bus for MCP yet
	)

	// Authentication Layer
	apiKey := os.Getenv("WARDSEAL_API_KEY")
	var identity *mcp.Identity

	if apiKey == "" {
		log.Warn("No WARDSEAL_API_KEY provided. MCP server will run in unauthenticated mode (CAUTION)")
	} else if apiKey == cfg.Directory.ServiceAuthToken.Raw() {
		log.Info("Authenticated via Master Service Token. Granting full access.")
		identity = &mcp.Identity{TenantID: "*", SubjectID: "admin"}
	} else {
		// Try to validate as a Workload API Key (ClientID:Secret)
		parts := strings.SplitN(apiKey, ":", 2)
		if len(parts) == 2 {
			clientID, secret := parts[0], parts[1]
			w, err := workloadRepo.GetByClientID(context.Background(), clientID)
			if err == nil {
				err = bcrypt.CompareHashAndPassword([]byte(w.ClientSecretHash), []byte(secret))
				if err == nil {
					log.Info("Authenticated securely via Workload API Key", zap.String("workload", w.Name), zap.String("tenant", w.TenantID))
					identity = &mcp.Identity{TenantID: w.TenantID, SubjectID: w.ID}
				} else {
					log.Error("Invalid API Key secret provided")
					os.Exit(1)
				}
			} else {
				log.Error("API Key ClientID not found", zap.String("client_id", clientID))
				os.Exit(1)
			}
		} else if strings.HasPrefix(apiKey, "vv_live_") {
			// Try to validate as a Dashboard API Key
			apiKeyRepo := auth.NewAPIKeyRepository(db)
			key, err := auth.ValidateAPIKey(context.Background(), apiKeyRepo, apiKey)
			if err == nil {
				log.Info("Authenticated securely via Dashboard API Key", zap.String("name", key.Name), zap.String("tenant", key.TenantID))
				identity = &mcp.Identity{TenantID: key.TenantID, SubjectID: key.OwnerID}
				// Async update last used
				go func() { _ = apiKeyRepo.UpdateLastUsed(context.Background(), key.ID) }()
			} else {
				log.Error("Invalid Dashboard API Key provided", zap.Error(err))
				os.Exit(1)
			}
		} else {
			log.Error("Invalid API Key format. Expected 'ClientID:Secret', 'vv_live_...' or Master Token")
			os.Exit(1)
		}
	}

	// Setup MCP Server
	server := mcp.NewServer("wardseal-mcp", "1.0.0", log)
	toolManager := mcp.NewToolManager(govSvc, identity)
	toolManager.RegisterTools(server)

	// Start the server (over stdin/stdout)
	log.Info("WardSeal MCP Server starting...")
	if err := server.Serve(); err != nil {
		log.Fatal("MCP server error", zap.Error(err))
	}
}
