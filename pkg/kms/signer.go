// Package kms provides Key Management Service abstractions for cryptographic operations.
// It supports multiple backends including local file-based keys and HashiCorp Vault Transit.
package kms

import (
	"context"
	"crypto/rsa"
	"fmt"

	"github.com/golang-jwt/jwt/v5"

	"github.com/dhawalhost/wardseal/pkg/types"
)

// Signer defines the interface for JWT signing operations.
type Signer interface {
	Sign(claims jwt.Claims) (string, error)
	KeyID() string
	PublicKey() *rsa.PublicKey
	Algorithm() string
	Close() error
}

// Cipher defines the interface for symmetric encryption/decryption operations.
type Cipher interface {
	Encrypt(ctx context.Context, plaintext []byte) ([]byte, error)
	Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error)
	Close() error
}

// Config holds configuration for KMS providers.
type Config struct {
	// Provider specifies the KMS backend: "local" or "vault"
	Provider string

	// Local file-based configuration
	PrivateKeyPath string
	PublicKeyPath  string
	MasterKey      types.Secret // Used for symmetric encryption (AES-256-GCM)

	// Vault configuration
	VaultAddr      string
	VaultToken     types.Secret
	VaultKeyName   string
	VaultKeyPath   string // Transit engine mount path (default: "transit")
	VaultNamespace string // Vault namespace (Enterprise only)

	// AppRole authentication (alternative to token)
	VaultRoleID   string
	VaultSecretID types.Secret
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
