package kms

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	vault "github.com/hashicorp/vault/api"
	vaultauth "github.com/hashicorp/vault/api/auth/approle"
)

// VaultSigner implements Signer using HashiCorp Vault Transit secrets engine.
// Keys never leave Vault - signing operations are performed server-side.
type VaultSigner struct {
	client     *vault.Client
	keyName    string
	keyPath    string // Transit engine mount path
	keyVersion int
	keyID      string
	publicKey  *rsa.PublicKey
}

// NewVaultSigner creates a new VaultSigner connected to HashiCorp Vault.
func NewVaultSigner(cfg Config) (*VaultSigner, error) {
	// Create Vault client
	vaultCfg := vault.DefaultConfig()
	vaultCfg.Address = cfg.VaultAddr

	client, err := vault.NewClient(vaultCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Set namespace if provided (Vault Enterprise)
	if cfg.VaultNamespace != "" {
		client.SetNamespace(cfg.VaultNamespace)
	}

	// Authenticate to Vault
	if err := authenticateVault(client, cfg); err != nil {
		return nil, fmt.Errorf("failed to authenticate to Vault: %w", err)
	}

	keyPath := cfg.VaultKeyPath
	if keyPath == "" {
		keyPath = "transit"
	}

	keyName := cfg.VaultKeyName
	if keyName == "" {
		keyName = "wardseal-signing-key"
	}

	signer := &VaultSigner{
		client:  client,
		keyName: keyName,
		keyPath: keyPath,
	}

	// Ensure key exists and fetch its public key
	if err := signer.initializeKey(); err != nil {
		return nil, fmt.Errorf("failed to initialize Vault key: %w", err)
	}

	return signer, nil
}

// authenticateVault handles Vault authentication (token or AppRole).
func authenticateVault(client *vault.Client, cfg Config) error {
	// If token is provided, use it directly
	if !cfg.VaultToken.IsEmpty() {
		client.SetToken(cfg.VaultToken.Raw())
		return nil
	}

	// Use AppRole authentication
	if cfg.VaultRoleID != "" && !cfg.VaultSecretID.IsEmpty() {
		appRoleAuth, err := vaultauth.NewAppRoleAuth(
			cfg.VaultRoleID,
			&vaultauth.SecretID{FromString: cfg.VaultSecretID.Raw()},
		)
		if err != nil {
			return fmt.Errorf("failed to create AppRole auth: %w", err)
		}

		authInfo, err := client.Auth().Login(context.Background(), appRoleAuth)
		if err != nil {
			return fmt.Errorf("AppRole authentication failed: %w", err)
		}

		if authInfo == nil {
			return fmt.Errorf("AppRole authentication returned nil")
		}

		return nil
	}

	return fmt.Errorf("no Vault authentication method configured (need VAULT_TOKEN or VAULT_ROLE_ID/VAULT_SECRET_ID)")
}

// initializeKey ensures the transit key exists and fetches its public key.
func (v *VaultSigner) initializeKey() error {
	ctx := context.Background()

	// Check if key exists
	keyPath := fmt.Sprintf("%s/keys/%s", v.keyPath, v.keyName)
	secret, err := v.client.Logical().ReadWithContext(ctx, keyPath)
	if err != nil {
		return fmt.Errorf("failed to read key: %w", err)
	}

	// Create key if it doesn't exist
	if secret == nil {
		createPath := fmt.Sprintf("%s/keys/%s", v.keyPath, v.keyName)
		_, err = v.client.Logical().WriteWithContext(ctx, createPath, map[string]interface{}{
			"type":                   "rsa-2048",
			"exportable":             false,
			"allow_plaintext_backup": false,
		})
		if err != nil {
			return fmt.Errorf("failed to create key: %w", err)
		}

		// Re-read to get key info
		secret, err = v.client.Logical().ReadWithContext(ctx, keyPath)
		if err != nil {
			return fmt.Errorf("failed to read created key: %w", err)
		}
	}

	// Extract key version and public key
	if secret == nil || secret.Data == nil {
		return fmt.Errorf("no key data returned from Vault")
	}

	// Get latest version
	latestVersion := 1
	if vers, ok := secret.Data["latest_version"].(json.Number); ok {
		v64, _ := vers.Int64()
		latestVersion = int(v64)
	} else if vers, ok := secret.Data["latest_version"].(float64); ok {
		latestVersion = int(vers)
	}
	v.keyVersion = latestVersion

	// Get public key from keys map
	keys, ok := secret.Data["keys"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("unexpected keys format in Vault response")
	}

	versionStr := fmt.Sprintf("%d", latestVersion)
	keyData, ok := keys[versionStr].(map[string]interface{})
	if !ok {
		return fmt.Errorf("key version %d not found", latestVersion)
	}

	pubKeyPEM, ok := keyData["public_key"].(string)
	if !ok {
		return fmt.Errorf("public_key not found in key data")
	}

	// Parse public key
	block, _ := pem.Decode([]byte(pubKeyPEM))
	if block == nil {
		return fmt.Errorf("failed to decode public key PEM")
	}

	pubKey, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %w", err)
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("key is not an RSA public key")
	}

	v.publicKey = rsaPubKey

	// Generate key ID from public key fingerprint
	pubKeyDER, _ := x509.MarshalPKIXPublicKey(rsaPubKey)
	hash := sha256.Sum256(pubKeyDER)
	v.keyID = hex.EncodeToString(hash[:8])

	return nil
}

// Sign creates a signed JWT token using Vault Transit.
func (v *VaultSigner) Sign(claims jwt.Claims) (string, error) {
	// Create unsigned token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = v.keyID

	// Get the signing string (header.payload)
	signingString, err := token.SigningString()
	if err != nil {
		return "", fmt.Errorf("failed to create signing string: %w", err)
	}

	// Hash with SHA-256 for RS256
	hash := sha256.Sum256([]byte(signingString))
	hashB64 := base64.StdEncoding.EncodeToString(hash[:])

	// Sign with Vault Transit
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	signPath := fmt.Sprintf("%s/sign/%s", v.keyPath, v.keyName)
	secret, err := v.client.Logical().WriteWithContext(ctx, signPath, map[string]interface{}{
		"input":               hashB64,
		"hash_algorithm":      "sha2-256",
		"signature_algorithm": "pkcs1v15",
		"prehashed":           true,
		"key_version":         v.keyVersion,
	})
	if err != nil {
		return "", fmt.Errorf("vault signing failed: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return "", fmt.Errorf("no signature returned from Vault")
	}

	// Extract signature
	signatureStr, ok := secret.Data["signature"].(string)
	if !ok {
		return "", fmt.Errorf("signature not found in Vault response")
	}

	// Vault returns signature in format: vault:v1:base64signature
	parts := strings.Split(signatureStr, ":")
	if len(parts) < 3 {
		return "", fmt.Errorf("unexpected signature format from Vault")
	}
	signatureB64 := parts[len(parts)-1]

	// Convert to URL-safe base64 for JWT
	signatureBytes, err := base64.StdEncoding.DecodeString(signatureB64)
	if err != nil {
		return "", fmt.Errorf("failed to decode signature: %w", err)
	}
	signatureURL := base64.RawURLEncoding.EncodeToString(signatureBytes)

	// Construct final JWT
	return signingString + "." + signatureURL, nil
}

// KeyID returns the key identifier.
func (v *VaultSigner) KeyID() string {
	return v.keyID
}

// PublicKey returns the RSA public key.
func (v *VaultSigner) PublicKey() *rsa.PublicKey {
	return v.publicKey
}

// Algorithm returns the signing algorithm.
func (v *VaultSigner) Algorithm() string {
	return "RS256"
}

// Close cleans up the Vault client.
func (v *VaultSigner) Close() error {
	// Vault client doesn't require explicit cleanup
	return nil
}
