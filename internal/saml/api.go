package saml

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	"github.com/dhawalhost/wardseal/pkg/kms"
	"github.com/dhawalhost/wardseal/pkg/middleware"
)

// HTTPHandler handles SAML SP and IdP management requests.
type HTTPHandler struct {
	store  *Store
	repo   IdPRepository
	cipher kms.Cipher
	logger *zap.Logger
}

// NewHTTPHandler creates a new SAML HTTP handler.
func NewHTTPHandler(store *Store, repo IdPRepository, cipher kms.Cipher, logger *zap.Logger) *HTTPHandler {
	return &HTTPHandler{store: store, repo: repo, cipher: cipher, logger: logger}
}

// RegisterRoutes registers SAML management routes.
func (h *HTTPHandler) RegisterRoutes(rg *gin.RouterGroup) {
	saml := rg.Group("/saml")
	{
		// Service Provider Management
		saml.GET("/providers", h.listProviders)
		saml.POST("/providers", h.createProvider)
		saml.GET("/providers/:entityID", h.getProvider)
		saml.DELETE("/providers/:entityID", h.deleteProvider)

		// Identity Provider Configuration (WardSeal as IdP)
		saml.GET("/idp", h.getIdPConfig)
		saml.POST("/idp", h.upsertIdPConfig)
	}
}

func (h *HTTPHandler) tenantID(c *gin.Context) (string, bool) {
	tenantID, err := middleware.TenantIDFromGinContext(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tenant id required"})
		return "", false
	}
	return tenantID, true
}

func (h *HTTPHandler) listProviders(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var providers []ServiceProvider
	err := h.store.db.SelectContext(c.Request.Context(), &providers, "SELECT * FROM saml_providers WHERE tenant_id = $1", tenantID)
	if err != nil {
		h.logger.Error("Failed to list providers", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

func (h *HTTPHandler) createProvider(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var input ServiceProvider
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.TenantID = tenantID
	input.CreatedAt = time.Now()
	input.UpdatedAt = time.Now()

	_, err := h.store.db.NamedExecContext(c.Request.Context(),
		`INSERT INTO saml_providers (entity_id, tenant_id, metadata_url, acs_url, certificate, created_at, updated_at) 
		 VALUES (:entity_id, :tenant_id, :metadata_url, :acs_url, :certificate, :created_at, :updated_at)`,
		input)

	if err != nil {
		h.logger.Error("Failed to create provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, input)
}

func (h *HTTPHandler) getProvider(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	entityID := c.Param("entityID")

	var sp ServiceProvider
	err := h.store.db.GetContext(c.Request.Context(), &sp, "SELECT * FROM saml_providers WHERE entity_id = $1 AND tenant_id = $2", entityID, tenantID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "provider not found"})
		return
	}

	c.JSON(http.StatusOK, sp)
}

func (h *HTTPHandler) deleteProvider(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}
	entityID := c.Param("entityID")

	_, err := h.store.db.ExecContext(c.Request.Context(), "DELETE FROM saml_providers WHERE entity_id = $1 AND tenant_id = $2", entityID, tenantID)
	if err != nil {
		h.logger.Error("Failed to delete provider", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func (h *HTTPHandler) getIdPConfig(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	cfg, err := h.repo.GetByTenantID(c.Request.Context(), tenantID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			c.JSON(http.StatusNotFound, gin.H{"error": "IdP not configured for this tenant"})
			return
		}
		h.logger.Error("Failed to get IdP config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Don't return the encrypted key
	cfg.EncryptedKey = nil
	c.JSON(http.StatusOK, cfg)
}

func (h *HTTPHandler) upsertIdPConfig(c *gin.Context) {
	tenantID, ok := h.tenantID(c)
	if !ok {
		return
	}

	var input IdPConfig
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	input.TenantID = tenantID

	// Automatic Certificate Generation if missing
	if input.Certificate == "" && input.EntityID != "" {
		h.logger.Info("Generating auto-signed credentials for SAML IdP", zap.String("tenant_id", tenantID), zap.String("entity_id", input.EntityID))
		cert, key, err := GenerateSelfSignedCredentials(input.EntityID)
		if err != nil {
			h.logger.Error("Failed to generate SAML credentials", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate credentials"})
			return
		}

		// Encrypt the generated key
		encryptedKey, err := h.cipher.Encrypt(c.Request.Context(), key)
		if err != nil {
			h.logger.Error("Failed to encrypt SAML private key", zap.Error(err))
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to secure credentials"})
			return
		}

		input.Certificate = string(cert)
		input.EncryptedKey = encryptedKey
	}

	err := h.repo.Upsert(c.Request.Context(), &input)
	if err != nil {
		h.logger.Error("Failed to upsert IdP config", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, input)
}
