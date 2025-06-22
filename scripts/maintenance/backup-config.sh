#!/bin/bash

# GamePlan Configuration Backup Script

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

BACKUP_DIR="./config-backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/manual_backup_${TIMESTAMP}.tar.gz"

mkdir -p "$BACKUP_DIR"

print_info "Creating manual backup..."

if [ -f ".env.production" ] && [ -f "docker-compose.production.yml" ]; then
    tar -czf "$BACKUP_FILE" .env.production docker-compose.production.yml docker-compose.yml
    print_status "Manual backup created: $BACKUP_FILE"
else
    echo "No configuration files to backup"
    exit 1
fi
