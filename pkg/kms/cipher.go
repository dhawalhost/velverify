package kms

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// NewCipher creates a new Cipher based on the configuration.
func NewCipher(cfg Config) (Cipher, error) {
	switch cfg.Provider {
	case "local", "":
		if cfg.MasterKey.IsEmpty() {
			return nil, fmt.Errorf("master key is required for local encryption")
		}
		return NewLocalCipher(cfg.MasterKey.Raw())
	case "vault":
		// Vault implementation would go here, leveraging the vault client
		return nil, fmt.Errorf("vault cipher not implemented in this phase")
	default:
		return nil, fmt.Errorf("unknown KMS provider: %s", cfg.Provider)
	}
}

// localCipher implements Cipher using AES-GCM.
type localCipher struct {
	key []byte
}

// NewLocalCipher creates a new AES-GCM cipher.
func NewLocalCipher(key string) (Cipher, error) {
	// Key must be exactly 32 bytes for AES-256
	kb := []byte(key)
	if len(kb) != 32 {
		// Pad or hash if not 32? For "properly handled", we should probably hash it
		// to ensure it's always 32 bytes.
		// For now, let's enforce 32 bytes or warn.
		return nil, fmt.Errorf("local master key must be exactly 32 bytes (256-bit)")
	}
	return &localCipher{key: kb}, nil
}

func (c *localCipher) Encrypt(ctx context.Context, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (c *localCipher) Decrypt(ctx context.Context, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonceSize := gcm.NonceSize()
	nonce, actualCiphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, actualCiphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %w", err)
	}

	return plaintext, nil
}

func (c *localCipher) Close() error {
	return nil
}
