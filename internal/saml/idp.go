package saml

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sync"

	"github.com/crewjam/saml/samlidp"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/kms"
	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// Config holds the configuration for the SAML Identity Provider factory.
type Config struct {
	BaseURL string
	Logger  *zap.Logger
	Cipher  kms.Cipher
	Repo    IdPRepository
	Store   samlidp.Store
}

// Provider represents the Multi-Tenant SAML Identity Provider.
type Provider struct {
	baseURL string
	logger  *zap.Logger
	cipher  kms.Cipher
	repo    IdPRepository
	store   samlidp.Store

	mu      sync.RWMutex
	servers map[string]*samlidp.Server
}

// NewProvider creates a new Multi-Tenant SAML Identity Provider.
func NewProvider(cfg Config) (*Provider, error) {
	return &Provider{
		baseURL: cfg.BaseURL,
		logger:  cfg.Logger,
		cipher:  cfg.Cipher,
		repo:    cfg.Repo,
		store:   cfg.Store,
		servers: make(map[string]*samlidp.Server),
	}, nil
}

// resolve retrieves or creates a SAML IdP server for the given tenant.
func (p *Provider) resolve(ctx context.Context, tenantID string) (*samlidp.Server, error) {
	p.mu.RLock()
	srv, ok := p.servers[tenantID]
	p.mu.RUnlock()
	if ok {
		return srv, nil
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Double check after lock
	if srv, ok := p.servers[tenantID]; ok {
		return srv, nil
	}

	// Fetch tenant-specific IdP config
	cfg, err := p.repo.GetByTenantID(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch IdP config for tenant %s: %w", tenantID, err)
	}

	cert, privKey, err := cfg.ParseCredentials(ctx, p.cipher)
	if err != nil {
		return nil, fmt.Errorf("failed to parse IdP credentials for tenant %s: %w", tenantID, err)
	}

	// Use tenant-specific baseURL or dynamic one based on slug?
	// For now, we use the global base URL. Real SaaS would use tenant-specific subdomains.
	baseURL, _ := url.Parse(p.baseURL)

	idpServer, err := samlidp.New(samlidp.Options{
		URL:         *baseURL,
		Key:         privKey,
		Certificate: cert,
		Logger:      zapLogger{p.logger},
		Store:       p.store,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create IDP server for tenant %s: %w", tenantID, err)
	}

	// Hardening: Set secure default signature method.
	// Signing is automatic since we provided a Key and Certificate.
	// Encryption is handled automatically if the SP metadata includes a certificate.
	idpServer.IDP.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"

	p.servers[tenantID] = idpServer
	return idpServer, nil
}

// ServeHTTP handles SAML requests with tenant resolution.
func (p *Provider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tenantID, err := middleware.TenantIDFromContext(r.Context())
	if err != nil {
		http.Error(w, "tenant identification failed", http.StatusUnauthorized)
		return
	}

	srv, err := p.resolve(r.Context(), tenantID)
	if err != nil {
		p.logger.Error("failed to resolve SAML IDP", zap.String("tenant_id", tenantID), zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	srv.ServeHTTP(w, r)
}

// ServeIDPInitiated handles IdP-initiated SSO flow for a tenant.
func (p *Provider) ServeIDPInitiated(w http.ResponseWriter, r *http.Request) {
	tenantID, err := middleware.TenantIDFromContext(r.Context())
	if err != nil {
		http.Error(w, "tenant identification failed", http.StatusUnauthorized)
		return
	}

	srv, err := p.resolve(r.Context(), tenantID)
	if err != nil {
		p.logger.Error("failed to resolve SAML IDP", zap.String("tenant_id", tenantID), zap.Error(err))
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	srv.HandleIDPInitiated(w, r)
}

// RegisterRoutes registers SAML IdP routes.
func (p *Provider) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("/saml/metadata", func(c *gin.Context) {
		p.ServeHTTP(c.Writer, c.Request)
	})
	rg.POST("/saml/sso", func(c *gin.Context) {
		p.ServeHTTP(c.Writer, c.Request)
	})
	rg.GET("/saml/sso", func(c *gin.Context) {
		p.ServeHTTP(c.Writer, c.Request)
	})
	rg.GET("/saml/idp-init", func(c *gin.Context) {
		p.ServeIDPInitiated(c.Writer, c.Request)
	})
}

// zapLogger adapts zap.Logger to the saml.Logger interface.
type zapLogger struct {
	logger *zap.Logger
}

func (l zapLogger) Print(v ...interface{}) {
	l.logger.Info(fmt.Sprint(v...))
}

func (l zapLogger) Printf(format string, v ...interface{}) {
	l.logger.Info(fmt.Sprintf(format, v...))
}

func (l zapLogger) Println(v ...interface{}) {
	l.logger.Info(fmt.Sprint(v...))
}

func (l zapLogger) Fatalf(format string, v ...interface{}) {
	l.logger.Fatal(fmt.Sprintf(format, v...))
}

func (l zapLogger) Fatal(v ...interface{}) {
	l.logger.Fatal(fmt.Sprint(v...))
}

func (l zapLogger) Fatalln(v ...interface{}) {
	l.logger.Fatal(fmt.Sprint(v...))
}

func (l zapLogger) Panicf(format string, v ...interface{}) {
	l.logger.Panic(fmt.Sprintf(format, v...))
}

func (l zapLogger) Panic(v ...interface{}) {
	l.logger.Panic(fmt.Sprint(v...))
}

func (l zapLogger) Panicln(v ...interface{}) {
	l.logger.Panic(fmt.Sprint(v...))
}
