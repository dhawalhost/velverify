# WardSeal Infrastructure & Deployment Makefile
# ============================================
# Senior DevOps authorized entrypoint for all platform operations.

# Configuration
SHELL := /bin/bash
COMPOSE_INFRA := docker-compose.yml
COMPOSE_APPS := docker-compose.apps.yml
COMPOSE_UI := docker-compose.ui.yml
COMPOSE_DEV := docker-compose.dev.yml
COMPOSE_CE := docker-compose.community.yml

# Default target
.PHONY: help
help: ## Show this help message
	@echo "WardSeal DevOps 2.0"
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# --- Initial Setup ---
.PHONY: setup
setup: ## Initialize local environment (.env, keys)
	@if [ ! -f .env ]; then cp .env.example .env && echo "Created .env from .env.example"; fi
	@mkdir -p deploy/dev-keys
	@if [ ! -f deploy/dev-keys/private_key.pem ]; then \
		echo "Generating development keys..."; \
		openssl genrsa -out deploy/dev-keys/private_key.pem 2048; \
		openssl rsa -in deploy/dev-keys/private_key.pem -pubout -out deploy/dev-keys/public_key.pem; \
	fi
	@echo "Setup complete. Please verify .env settings."

# --- Development Flow ---
.PHONY: infra-up
infra-up: ## Start only infrastructure (DB, Redis, Traefik)
	docker compose -f $(COMPOSE_INFRA) up -d
	@echo "Waiting for PostgreSQL to be healthy..."
	@until docker exec wardseal-postgres pg_isready -U user -d identity_platform > /dev/null 2>&1; do sleep 1; done
	@echo "Infrastructure is ready."

.PHONY: dev
dev: infra-up ## Start infrastructure and build apps locally
	docker compose -f $(COMPOSE_INFRA) -f $(COMPOSE_APPS) -f $(COMPOSE_UI) up --build -d

.PHONY: down
down: ## Stop all containers
	docker compose -f $(COMPOSE_INFRA) -f $(COMPOSE_APPS) -f $(COMPOSE_UI) down

.PHONY: clean
clean: down ## Stop all containers and remove volumes
	docker compose -f $(COMPOSE_INFRA) -f $(COMPOSE_APPS) -f $(COMPOSE_UI) down -v
	rm -rf bin/
	rm -f coverage.out coverage.html

# --- Quality Assurance (QA) ---
.PHONY: fmt
fmt: ## Format Go code
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run --fix ./...
	go run golang.org/x/tools/cmd/goimports@latest -w -local github.com/dhawalhost/wardseal .

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest run --timeout=15m ./...

.PHONY: tidy
tidy: ## Tidy go modules
	go mod tidy

.PHONY: deps
deps: ## Download dependencies
	go mod download
	go mod tidy

.PHONY: generate
generate: ## Run go generate
	go generate ./...

.PHONY: coverage
coverage: ## Run tests with coverage report
	go test -v -race -coverprofile=coverage.out -covermode=atomic ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# --- Validation & Config ---
.PHONY: validate-env-config
validate-env-config: ## Validate Helm chart environment consistency
	./scripts/validate_env_config.sh

.PHONY: config-lint
config-lint: validate-env-config ## Alias for CI configuration linting

# --- Local Kubernetes (Rancher Desktop) ---
.PHONY: sync-charts
sync-charts: ## Sync local Helm sub-charts
	bash scripts/deploy_local_k8s.sh --sync-charts-only

.PHONY: deploy-local-k8s
deploy-local-k8s: ## Full local Kubernetes deployment
	bash scripts/deploy_local_k8s.sh

.PHONY: destroy-local-k8s
destroy-local-k8s: ## Tear down local Kubernetes resources
	bash scripts/destroy_local_k8s.sh

# --- Community Edition ---
.PHONY: community
community: infra-up ## Start pre-built Community Edition (Zero-Conf)
	docker compose -f $(COMPOSE_INFRA) -f $(COMPOSE_CE) up -d
	@echo "WardSeal Community Edition is starting at http://manage.wardseal.local"

# --- Debugging & Logs ---
.PHONY: logs
logs: ## Stream all container logs
	docker compose -f $(COMPOSE_INFRA) -f $(COMPOSE_APPS) -f $(COMPOSE_UI) logs -f

.PHONY: debug-svc
debug-svc: ## Run a specific service with Delve debugger (Usage: make debug-svc NAME=authsvc)
	@if [ -z "$(NAME)" ]; then echo "Error: NAME is required (e.g., make debug-svc NAME=authsvc)"; exit 1; fi
	@echo "Coming soon: Automated Delve orchestration for $(NAME)"

# --- Build & Release ---
.PHONY: build-all
build-all: ## Build all backend service binaries and CLI tools locally
	@mkdir -p bin
	go build -o bin/authsvc ./cmd/authsvc
	go build -o bin/dirsvc ./cmd/dirsvc
	go build -o bin/govsvc ./cmd/govsvc
	go build -o bin/policysvc ./cmd/policysvc
	go build -o bin/provsvc ./cmd/provsvc
	go build -o bin/wardseal ./cmd/wardseal
	go build -o bin/mcpsvc ./cmd/mcpsvc
	go build -o bin/migrate_patch ./cmd/migrate_patch

.PHONY: mcp
mcp: ## Run the MCP server locally
	go run cmd/mcpsvc/main.go

.PHONY: images
images: ## Build all Docker images
	docker compose -f $(COMPOSE_APPS) -f $(COMPOSE_UI) build

# --- Testing ---
.PHONY: test
test: ## Run unit tests
	go test -v -race -short ./...

.PHONY: test-integration
test-integration: infra-up ## Run integration tests against live infrastructure
	APP_DATABASE_HOST=localhost \
	APP_DATABASE_USER=user \
	APP_DATABASE_PASSWORD=password \
	APP_DATABASE_NAME=identity_platform \
	go test -v -tags=integration ./tests/integration/...

.PHONY: ui
ui: ## Build and run the UI locally
	cd web/admin && npm install && npm run dev

.PHONY: build-ui
build-ui: ## Build the UI for production
	cd web/admin && npm install && npm run build

.PHONY: build-all-images
build-all-images: ## Build all Docker images
	docker compose -f $(COMPOSE_APPS) -f $(COMPOSE_UI) build