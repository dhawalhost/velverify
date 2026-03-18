package governance

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jmoiron/sqlx"
	"go.uber.org/zap"
)

// DomainVerificationHandler handles domain verification API requests.
type DomainVerificationHandler struct {
	db     *sqlx.DB
	store  OrganizationRepository
	logger *zap.Logger
}

// NewDomainVerificationHandler creates a new domain verification handler.
func NewDomainVerificationHandler(db *sqlx.DB, store OrganizationRepository, logger *zap.Logger) *DomainVerificationHandler {
	return &DomainVerificationHandler{db: db, store: store, logger: logger}
}

// RegisterRoutes registers domain verification routes.
func (h *DomainVerificationHandler) RegisterRoutes(rg *gin.RouterGroup) {
	rg.GET("/organizations/:id/domain-verification", h.getDomainVerification)
	rg.POST("/organizations/:id/domain-verification/generate", h.generateVerificationToken)
	rg.POST("/organizations/:id/domain-verification/verify", h.verifyDomain)
}

// DomainVerificationResponse contains verification details.
type DomainVerificationResponse struct {
	Domain       string     `json:"domain"`
	Token        string     `json:"token,omitempty"`
	TxtRecord    string     `json:"txt_record"`
	Instructions string     `json:"instructions"`
	Verified     bool       `json:"verified"`
	ExpiresAt    *time.Time `json:"expires_at,omitempty"`
}

func (h *DomainVerificationHandler) getDomainVerification(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	orgID := c.Param("id")
	org, err := h.store.Get(c.Request.Context(), tenantID, orgID)
	if err != nil || org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}

	if org.Domain == nil || *org.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization has no domain configured"})
		return
	}

	// Get verification token from DB
	var token *string
	var expiresAt *time.Time
	query := `SELECT domain_verification_token, domain_verification_expires_at FROM organizations WHERE id = $1`
	row := h.db.QueryRowContext(c.Request.Context(), query, orgID)
	_ = row.Scan(&token, &expiresAt)

	resp := DomainVerificationResponse{
		Domain:       *org.Domain,
		Verified:     org.DomainVerified,
		TxtRecord:    fmt.Sprintf("_wardseal.%s", *org.Domain),
		Instructions: "Add a TXT record to your DNS with the name and value shown below.",
	}

	if token != nil {
		resp.Token = *token
		resp.ExpiresAt = expiresAt
	}

	c.JSON(http.StatusOK, resp)
}

func (h *DomainVerificationHandler) generateVerificationToken(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	orgID := c.Param("id")
	org, err := h.store.Get(c.Request.Context(), tenantID, orgID)
	if err != nil || org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}

	if org.Domain == nil || *org.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization has no domain configured"})
		return
	}

	// Generate random token
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate token"})
		return
	}
	token := "wardseal-verify=" + hex.EncodeToString(tokenBytes)
	expiresAt := time.Now().Add(7 * 24 * time.Hour) // 7 days validity

	// Store token
	query := `UPDATE organizations SET domain_verification_token = $1, domain_verification_expires_at = $2, domain_verified = FALSE WHERE id = $3`
	if _, err := h.db.ExecContext(c.Request.Context(), query, token, expiresAt, orgID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save token"})
		return
	}

	c.JSON(http.StatusOK, DomainVerificationResponse{
		Domain:       *org.Domain,
		Token:        token,
		TxtRecord:    fmt.Sprintf("_wardseal.%s", *org.Domain),
		Instructions: fmt.Sprintf("Add a TXT record:\n  Name: _wardseal.%s\n  Value: %s", *org.Domain, token),
		Verified:     false,
		ExpiresAt:    &expiresAt,
	})
}

func (h *DomainVerificationHandler) verifyDomain(c *gin.Context) {
	tenantID := c.GetHeader("X-Tenant-ID")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "X-Tenant-ID header required"})
		return
	}

	orgID := c.Param("id")
	org, err := h.store.Get(c.Request.Context(), tenantID, orgID)
	if err != nil || org == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "organization not found"})
		return
	}

	if org.Domain == nil || *org.Domain == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization has no domain configured"})
		return
	}

	// Get expected token
	var token *string
	var expiresAt *time.Time
	query := `SELECT domain_verification_token, domain_verification_expires_at FROM organizations WHERE id = $1`
	if err := h.db.QueryRowContext(c.Request.Context(), query, orgID).Scan(&token, &expiresAt); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no verification token generated"})
		return
	}

	if token == nil || *token == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "no verification token generated"})
		return
	}

	if expiresAt != nil && time.Now().After(*expiresAt) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "verification token expired, please generate a new one"})
		return
	}

	// Perform DNS TXT lookup
	txtRecordName := fmt.Sprintf("_wardseal.%s", *org.Domain)
	verified := verifyDNSTxtRecord(c.Request.Context(), txtRecordName, *token)

	if verified {
		// Mark domain as verified
		updateQuery := `UPDATE organizations SET domain_verified = TRUE WHERE id = $1`
		_, _ = h.db.ExecContext(c.Request.Context(), updateQuery, orgID)

		c.JSON(http.StatusOK, gin.H{
			"verified": true,
			"message":  "Domain successfully verified!",
		})
	} else {
		c.JSON(http.StatusOK, gin.H{
			"verified": false,
			"message":  fmt.Sprintf("TXT record not found or doesn't match. Expected: %s at %s", *token, txtRecordName),
		})
	}
}

func verifyDNSTxtRecord(ctx context.Context, hostname, expectedValue string) bool {
	records, err := net.LookupTXT(hostname)
	if err != nil {
		return false
	}

	for _, record := range records {
		if strings.TrimSpace(record) == expectedValue {
			return true
		}
	}
	return false
}
