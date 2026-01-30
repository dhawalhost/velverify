package kms

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

// LocalSigner implements Signer using local file-based RSA keys.
type LocalSigner struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
}

// NewLocalSigner creates a new LocalSigner from PEM-encoded key files.
func NewLocalSigner(privateKeyPath, publicKeyPath string) (*LocalSigner, error) {
	// If no paths provided, generate ephemeral keys for development
	if privateKeyPath == "" && publicKeyPath == "" {
		return newEphemeralSigner()
	}

	// Load private key
	privateKey, err := loadPrivateKey(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load private key: %w", err)
	}

	// Load public key (or derive from private)
	var publicKey *rsa.PublicKey
	if publicKeyPath != "" {
		publicKey, err = loadPublicKey(publicKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load public key: %w", err)
		}
	} else {
		publicKey = &privateKey.PublicKey
	}

	// Generate key ID from public key fingerprint
	keyID := generateKeyID(publicKey)

	return &LocalSigner{
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      keyID,
	}, nil
}

// newEphemeralSigner creates a signer with in-memory generated keys.
// This is only for development/testing.
func newEphemeralSigner() (*LocalSigner, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ephemeral key: %w", err)
	}

	keyID := generateKeyID(&privateKey.PublicKey)

	return &LocalSigner{
		privateKey: privateKey,
		publicKey:  &privateKey.PublicKey,
		keyID:      keyID,
	}, nil
}

// Sign creates a signed JWT token from the given claims.
func (s *LocalSigner) Sign(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyID

	signedToken, err := token.SignedString(s.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return signedToken, nil
}

// KeyID returns the key identifier.
func (s *LocalSigner) KeyID() string {
	return s.keyID
}

// PublicKey returns the RSA public key.
func (s *LocalSigner) PublicKey() *rsa.PublicKey {
	return s.publicKey
}

// Algorithm returns the signing algorithm.
func (s *LocalSigner) Algorithm() string {
	return "RS256"
}

// Close is a no-op for local signer.
func (s *LocalSigner) Close() error {
	return nil
}

// loadPrivateKey reads and parses a PEM-encoded RSA private key.
func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: trusted path from config
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	// Try PKCS#8 first, then PKCS#1
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse private key: %w", err)
		}
	}

	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA private key")
	}

	return rsaKey, nil
}

// loadPublicKey reads and parses a PEM-encoded RSA public key.
func loadPublicKey(path string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: trusted path from config
	if err != nil {
		return nil, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaKey, ok := key.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not an RSA public key")
	}

	return rsaKey, nil
}

// generateKeyID creates a key ID from the public key fingerprint.
func generateKeyID(pubKey *rsa.PublicKey) string {
	pubKeyDER, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "default-key-id"
	}
	hash := sha256.Sum256(pubKeyDER)
	return hex.EncodeToString(hash[:8])
}
