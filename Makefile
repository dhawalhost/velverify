# Identity Platform Makefile
# ===========================

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
BINARY_NAME=identity-platform

# Services
SERVICES=authsvc dirsvc govsvc policysvc provsvc wardseal

# Migration parameters
MIGRATE_VERSION = v4.15.2
MIGRATE_OS = $(shell go env GOOS)
MIGRATE_ARCH = $(shell go env GOARCH)
MIGRATE_PATH = ./scripts/migrate
MIGRATE_CMD = $(MIGRATE_PATH)/migrate -path migrations -database 'postgres://user:password@localhost:5432/identity_platform?sslmode=disable'

# Test database
TEST_DB_URL = postgres://user:password@localhost:5432/identity_platform_test?sslmode=disable

# Docker parameters
BUILD_IMAGE_PREFIX?=ghcr.io/dhawalhost

# Lint parameters
GOLANGCI_LINT_VERSION = v2.7.2

.PHONY: all build clean deps test lint test-coverage test-integration \
        docker-up docker-down install-migrate migrate-create migrate-up migrate-down \
        build-images push-images run-authsvc run-dirsvc run-govsvc \
	install-tools lint-fix fmt help validate-env-config \
	sync-charts deploy-local-k8s destroy-local-k8s

# ==================
# Main targets
# ==================

all: lint test build ## Run lint, tests, and build

help: ## Show this help message
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

# ==================
# Development
# ==================

build: ## Build all service binaries
	@mkdir -p bin
	@for svc in $(SERVICES); do \
		echo "Building $$svc..."; \
		$(GOBUILD) -o bin/$$svc ./cmd/$$svc; \
	done

build-cli: ## Build the wardseal CLI binary
	@echo "Building wardseal CLI..."
	@mkdir -p bin
	$(GOBUILD) -o bin/wardseal ./cmd/wardseal

clean: ## Clean build artifacts
	$(GOCLEAN)
	rm -rf bin/
	rm -f coverage.out coverage.html

deps: ## Download dependencies
	$(GOMOD) download
	$(GOMOD) tidy

fmt: ## Format Go code
	gofmt -s -w .
	goimports -w -local github.com/dhawalhost/wardseal .

# ==================
# Linting
# ==================

install-lint: ## Install golangci-lint
	@echo "Installing golangci-lint..."
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

lint: ## Run linter
	golangci-lint run --timeout=5m ./...

lint-fix: ## Run linter with auto-fix
	golangci-lint run --fix --timeout=5m ./...

# ==================
# Testing
# ==================

test: ## Run unit tests
	$(GOTEST) -v -race -short ./...

test-coverage: ## Run tests with coverage report
	$(GOTEST) -v -race -coverprofile=coverage.out -covermode=atomic ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

test-integration: ## Run integration tests (requires PostgreSQL)
	@echo "Running integration tests..."
	TEST_DB_HOST=127.0.0.1 \
	TEST_DB_USER=user \
	TEST_DB_PASSWORD=password \
	TEST_DB_NAME=identity_platform_test \
	$(GOTEST) -v -tags=integration ./tests/integration/...

test-integration-setup: docker-up ## Setup database for integration tests
	@echo "Creating test database..."
	@sleep 3
	@docker exec -it $$(docker-compose ps -q postgres) psql -U user -d postgres -c "CREATE DATABASE identity_platform_test;" 2>/dev/null || true
	@echo "Running migrations on test database..."
	$(MIGRATE_PATH)/migrate -path migrations -database "$(TEST_DB_URL)" up

test-all: test test-integration ## Run all tests

# ==================
# Running services locally
# ==================

run-authsvc: ## Run auth service locally
	DB_HOST=localhost \
	DIRECTORY_SERVICE_URL=http://localhost:8081 \
	$(GOCMD) run ./cmd/authsvc

run-dirsvc: ## Run directory service locally
	DB_HOST=localhost \
	$(GOCMD) run ./cmd/dirsvc

run-govsvc: ## Run governance service locally
	DB_HOST=localhost \
	DIRECTORY_SERVICE_URL=http://localhost:8081 \
	$(GOCMD) run ./cmd/govsvc

run-all: docker-up ## Run all services (requires docker-compose)
	./scripts/run_local.sh

# ==================
# Docker
# ==================

docker-up: ## Start Docker containers
	docker-compose up -d

docker-down: ## Stop Docker containers
	docker-compose down

docker-logs: ## View Docker logs
	docker-compose logs -f

build-images: ## Build all Docker images
	@for svc in $(SERVICES); do \
		if [ -f cmd/$$svc/Dockerfile ]; then \
			echo "Building $$svc image..."; \
			docker build -t $(BUILD_IMAGE_PREFIX)/$$svc:latest -f cmd/$$svc/Dockerfile .; \
		fi; \
	done
	@if [ -f web/admin/Dockerfile ]; then \
		echo "Building admin-ui image..."; \
		docker build -t $(BUILD_IMAGE_PREFIX)/admin-ui:latest -f web/admin/Dockerfile web/admin; \
	fi

push-images: ## Push all Docker images
	@for svc in $(SERVICES); do \
		echo "Pushing $$svc..."; \
		docker push $(BUILD_IMAGE_PREFIX)/$$svc:latest; \
	done
	docker push $(BUILD_IMAGE_PREFIX)/admin-ui:latest

# ==================
# Migrations
# ==================

install-migrate: ## Install migrate tool
	@mkdir -p $(MIGRATE_PATH)
	@echo "Downloading migrate..."
	@curl -L https://github.com/golang-migrate/migrate/releases/download/$(MIGRATE_VERSION)/migrate.$(MIGRATE_OS)-$(MIGRATE_ARCH).tar.gz | tar xvz -C $(MIGRATE_PATH)
	@mv $(MIGRATE_PATH)/migrate.$(MIGRATE_OS)-$(MIGRATE_ARCH) $(MIGRATE_PATH)/migrate 2>/dev/null || true
	@chmod +x $(MIGRATE_PATH)/migrate

migrate-create: ## Create a new migration
	@read -p "Enter migration name: " name; \
	$(MIGRATE_CMD) create -ext sql -dir migrations -seq $$name

migrate-up: ## Apply all migrations
	$(MIGRATE_CMD) up

migrate-down: ## Rollback all migrations
	$(MIGRATE_CMD) down

migrate-status: ## Show migration status
	$(MIGRATE_CMD) version

# ==================
# Tools
# ==================

install-tools: install-lint install-migrate ## Install all development tools
	go install golang.org/x/tools/cmd/goimports@latest
	@echo "All tools installed!"

# ==================
# Frontend
# ==================

frontend-install: ## Install frontend dependencies
	cd web/admin && npm install

frontend-dev: ## Run frontend in development mode
	cd web/admin && npm run dev

frontend-build: ## Build frontend for production
	cd web/admin && npm run build

frontend-lint: ## Lint frontend code
	cd web/admin && npm run lint

validate-env-config: ## Validate local/staging/production Helm config consistency
	./scripts/validate_env_config.sh

config-lint: validate-env-config ## Alias for CI config lint checks

# ==================
# Local k8s (Rancher Desktop)
# ==================

sync-charts: ## Sync local Helm sub-charts, update Chart.lock, and verify dependencies
	bash scripts/deploy_local_k8s.sh --sync-charts-only

deploy-local-k8s: ## Full local k8s deploy (includes image build + chart sync)
	bash scripts/deploy_local_k8s.sh

deploy-local-k8s-fast: ## Redeploy without rebuilding images (~30s — use after first deploy)
	bash scripts/deploy_local_k8s.sh --skip-build --skip-infra --skip-sync

deploy-local-k8s-no-landing: ## Full deploy, skip landing site build
	bash scripts/deploy_local_k8s.sh --without-landing

destroy-local-k8s: ## Tear down local k8s resources
	bash scripts/destroy_local_k8s.sh

destroy-local-k8s-clean: ## Tear down local k8s resources and remove /etc/hosts entries
	bash scripts/destroy_local_k8s.sh --remove-hosts