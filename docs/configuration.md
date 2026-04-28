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
├── .env                 # Local development configuration (gitignored)
├── .env.example         # Template for environment settings
├── docker-compose.yml   # Infrastructure orchestration
└── Makefile             # Command orchestration (make dev)
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

1. Copy the environment template:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your local settings (this file is gitignored).

3. Run the orchestration stack:
   ```bash
   make dev
   ```

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
