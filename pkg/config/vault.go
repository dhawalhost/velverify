package config

import (
	"context"
	"fmt"
	"time"

	vault "github.com/hashicorp/vault/api"
	vaultauth "github.com/hashicorp/vault/api/auth/approle"
)

// vaultClientImpl implements VaultClient interface.
type vaultClientImpl struct {
	client *vault.Client
}

// newVaultClient creates a new Vault client.
func newVaultClient() (VaultClient, error) {
	config := vault.DefaultConfig()

	client, err := vault.NewClient(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create Vault client: %w", err)
	}

	// Authenticate
	if err := authenticateVault(client); err != nil {
		return nil, fmt.Errorf("failed to authenticate to Vault: %w", err)
	}

	return &vaultClientImpl{client: client}, nil
}

// authenticateVault handles Vault authentication.
func authenticateVault(client *vault.Client) error {
	// Try token first
	if token := getEnv("VAULT_TOKEN"); token != "" {
		client.SetToken(token)
		return nil
	}

	// Try AppRole
	roleID := getEnv("VAULT_ROLE_ID")
	secretID := getEnv("VAULT_SECRET_ID")
	if roleID != "" && secretID != "" {
		appRoleAuth, err := vaultauth.NewAppRoleAuth(
			roleID,
			&vaultauth.SecretID{FromString: secretID},
		)
		if err != nil {
			return fmt.Errorf("failed to create AppRole auth: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		authInfo, err := client.Auth().Login(ctx, appRoleAuth)
		if err != nil {
			return fmt.Errorf("AppRole authentication failed: %w", err)
		}

		if authInfo == nil {
			return fmt.Errorf("AppRole authentication returned nil")
		}

		return nil
	}

	return fmt.Errorf("no Vault authentication method configured (set VAULT_TOKEN or VAULT_ROLE_ID/VAULT_SECRET_ID)")
}

// ReadSecret reads secrets from Vault KV v2.
func (v *vaultClientImpl) ReadSecret(path string) (map[string]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	secret, err := v.client.Logical().ReadWithContext(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("failed to read secret: %w", err)
	}

	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret not found at path: %s", path)
	}

	// KV v2 stores data under "data" key
	data, ok := secret.Data["data"].(map[string]interface{})
	if !ok {
		// Try KV v1 format
		data = secret.Data
	}

	result := make(map[string]string)
	for k, v := range data {
		if str, ok := v.(string); ok {
			result[k] = str
		}
	}

	return result, nil
}

// Close closes the Vault client.
func (v *vaultClientImpl) Close() error {
	// Vault client doesn't require explicit cleanup
	return nil
}

// getEnv is a helper to get environment variable.
func getEnv(key string) string {
	return lookupEnv(key)
}

// lookupEnv returns environment variable value.
func lookupEnv(key string) string {
	// Import os at top of file is already done in config.go
	// This is just a helper wrapper
	val, _ := lookupEnvOS(key)
	return val
}
