# Configuration Management

WardSeal uses a hybrid configuration system that loads settings from multiple sources.

## Configuration Sources (Priority Order)

1. **Default values** (built-in) - Lowest priority
2. **`.env.defaults`** - Non-secrets, checked into git
3. **`.env.{environment}`** - Environment-specific non-secrets
4. **HashiCorp Vault** - Secrets (if `VAULT_ADDR` is set)
5. **OS Environment Variables** - Highest priority (overrides all)

## File Structure

```
config/
├── .env.defaults        # Base config, in git
├── .env.development     # Local dev, gitignored (has dev secrets)
├── .env.staging         # Staging non-secrets, in git
└── .env.production      # Production non-secrets, in git
```

## Usage

### In Go Services

```go
import "github.com/dhawalhost/wardseal/pkg/config"

func main() {
    // Load configuration (auto-detects environment)
    cfg, err := config.Load()
    if err != nil {
        log.Fatal(err)
    }

    // Use configuration
    db.Connect(cfg.Database.ConnectionString())
}
```

### Environment Detection

The environment is determined by the `ENVIRONMENT` variable:
- `development` (default)
- `staging`
- `production`

## Local Development

1. Copy the development template:
   ```bash
   cp config/.env.development.example config/.env.development
   ```

2. Edit with your local settings (this file is gitignored)

3. Run services - config loads automatically

## Staging/Production with Vault

1. Set Vault environment variables:
   ```bash
   export VAULT_ADDR=https://vault.example.com
   export VAULT_TOKEN=xxx  # or use AppRole
   export ENVIRONMENT=staging
   ```

2. Store secrets in Vault:
   ```bash
   vault kv put secret/wardseal/staging \
       DB_PASSWORD=xxx \
       SERVICE_AUTH_TOKEN=yyy \
       WEBHOOK_SECRET=zzz
   ```

3. Secrets are automatically loaded and merged with `.env.staging`

## Secret Rotation

The config package supports automatic refresh:

```go
loader := config.NewLoader()
cfg, _ := loader.Load()

// Refresh every 5 minutes
loader.StartAutoRefresh(5*time.Minute, func(newCfg *config.Config) {
    // Update your application with new config
    updateConfig(newCfg)
})
```

## Configuration Reference

See [environment-variables.md](environment-variables.md) for complete variable list.
