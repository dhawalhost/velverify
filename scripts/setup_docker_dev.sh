#!/bin/bash
set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Starting Local Development Setup (Docker Compose)...${NC}"

# Check dependencies
if ! command -v docker &> /dev/null; then
    echo "Error: docker not found."
    exit 1
fi

# Remove deprecated version warning
sed -i '' '/^version:/d' docker-compose.yml 2>/dev/null || true

echo -e "${GREEN}Step 1: Starting Database and Redis...${NC}"
docker compose up -d postgres redis
echo "Waiting for Postgres to be ready..."
until docker compose exec -T postgres pg_isready -U user -d identity_platform 2>/dev/null; do
  sleep 2
done
echo -e "${GREEN}Database is ready!${NC}"

echo -e "${GREEN}Step 2: Running Migrations...${NC}"
# Use golang-migrate container on the same network
docker run --rm --network wardseal_default \
  -v "$(pwd)/migrations:/migrations" \
  migrate/migrate \
  -path=/migrations/ \
  -database "postgres://user:password@postgres:5432/identity_platform?sslmode=disable" \
  up || echo -e "${YELLOW}Migrations may have already been applied.${NC}"

echo -e "${GREEN}Step 3: Building and Starting Services...${NC}"
# Build and start services sequentially to avoid resource exhaustion
# Core services first
echo "Building dirsvc..."
docker compose build dirsvc
echo "Starting dirsvc..."
docker compose up -d dirsvc

echo "Building authsvc..."
docker compose build authsvc
echo "Starting authsvc..."
docker compose up -d authsvc

echo "Building govsvc..."
docker compose build govsvc
echo "Starting govsvc..."
docker compose up -d govsvc

# Optional services
echo "Building policysvc..."
docker compose build policysvc
echo "Starting policysvc..."
docker compose up -d policysvc

echo "Building provsvc..."
docker compose build provsvc
echo "Starting provsvc..."
docker compose up -d provsvc

# Frontend
echo "Building adminui..."
docker compose build adminui
echo "Starting adminui..."
docker compose up -d adminui

echo ""
echo -e "${GREEN}Setup Complete!${NC}"
echo "================================================"
echo "Admin UI:          http://localhost:5173"
echo "Auth Service:      http://localhost:8080"
echo "Directory Service: http://localhost:8081"
echo "Governance Service: http://localhost:8082"
echo "================================================"
echo ""
echo "View logs: docker compose logs -f"
echo "Stop all:  docker compose down"
