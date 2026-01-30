// Package kms provides Key Management Service abstractions for cryptographic operations.
// It supports multiple backends including local file-based keys and HashiCorp Vault Transit.
package kms

import (
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"
)

// Signer defines the interface for JWT signing operations.
// Implementations can use local keys or external KMS providers like Vault.
type Signer interface {
	// Sign creates a signed JWT token from the given claims.
	Sign(claims jwt.Claims) (string, error)

	// KeyID returns the key identifier used in JWT headers.
	KeyID() string

	// PublicKey returns the RSA public key for token verification.
	PublicKey() *rsa.PublicKey

	// Algorithm returns the signing algorithm (e.g., "RS256").
	Algorithm() string

	// Close releases any resources held by the signer.
	Close() error
}

// Config holds configuration for KMS providers.
type Config struct {
	// Provider specifies the KMS backend: "local" or "vault"
	Provider string

	// Local file-based configuration
	PrivateKeyPath string
	PublicKeyPath  string

	// Vault configuration
	VaultAddr      string
	VaultToken     string
	VaultKeyName   string
	VaultKeyPath   string // Transit engine mount path (default: "transit")
	VaultNamespace string // Vault namespace (Enterprise only)

	// AppRole authentication (alternative to token)
	VaultRoleID   string
	VaultSecretID string
}

// NewSigner creates a new Signer based on the configuration.
func NewSigner(cfg Config) (Signer, error) {
	switch cfg.Provider {
	case "local", "":
		return NewLocalSigner(cfg.PrivateKeyPath, cfg.PublicKeyPath)
	case "vault":
		return NewVaultSigner(cfg)
	default:
		return nil, fmt.Errorf("unknown KMS provider: %s", cfg.Provider)
	}
}
