#!/bin/bash

# GamePlan Safe Update Deployment Script
# This script safely updates the application while preserving configuration

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
BACKUP_DIR="./config-backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/config_backup_${TIMESTAMP}.tar.gz"

echo -e "${BLUE}🚀 GamePlan Safe Update Deployment Script${NC}"
echo -e "${BLUE}==========================================${NC}"

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

print_info "Starting safe update process..."

# Step 1: Backup current configuration
print_info "Step 1: Backing up current configuration..."
if [ -f ".env.production" ] && [ -f "docker-compose.production.yml" ]; then
    tar -czf "$BACKUP_FILE" .env.production docker-compose.production.yml docker-compose.yml 2>/dev/null || true
    print_status "Configuration backed up to $BACKUP_FILE"
else
    print_warning "No existing protected configuration found"
fi

# Step 2: Check if services are running
print_info "Step 2: Checking current service status..."
if docker compose ps | grep -q "Up"; then
    SERVICES_RUNNING=true
    print_status "Services are currently running"
else
    SERVICES_RUNNING=false
    print_warning "Services are not running"
fi

# Step 3: Stop services gracefully
if [ "$SERVICES_RUNNING" = true ]; then
    print_info "Step 3: Stopping services gracefully..."
    docker compose down
    print_status "Services stopped"
fi

# Step 4: Backup current docker-compose.yml
print_info "Step 4: Backing up current docker-compose.yml..."
if [ -f "docker-compose.yml" ]; then
    cp docker-compose.yml "docker-compose.yml.backup_$TIMESTAMP"
    print_status "docker-compose.yml backed up"
fi

# Step 5: Pull latest changes from git
print_info "Step 5: Pulling latest changes from git..."
if git pull origin main; then
    print_status "Git pull completed successfully"
else
    print_error "Git pull failed! Restoring backup..."
    if [ -f "docker-compose.yml.backup_$TIMESTAMP" ]; then
        cp "docker-compose.yml.backup_$TIMESTAMP" docker-compose.yml
        print_status "docker-compose.yml restored from backup"
    fi
    exit 1
fi

# Step 6: Ensure protected files exist
print_info "Step 6: Verifying protected configuration files..."
if [ ! -f ".env.production" ]; then
    print_error "Protected .env.production file missing! Please run initial setup."
    exit 1
fi

if [ ! -f "docker-compose.production.yml" ]; then
    print_error "Protected docker-compose.production.yml file missing! Please run initial setup."
    exit 1
fi

print_status "Protected configuration files verified"

# Step 7: Update .gitignore to protect our files
print_info "Step 7: Updating .gitignore to protect configuration files..."
if ! grep -q ".env.production" .gitignore 2>/dev/null; then
    echo ".env.production" >> .gitignore
fi
if ! grep -q "docker-compose.production.yml" .gitignore 2>/dev/null; then
    echo "docker-compose.production.yml" >> .gitignore
fi
if ! grep -q "config-backups/" .gitignore 2>/dev/null; then
    echo "config-backups/" >> .gitignore
fi
print_status ".gitignore updated"

# Step 8: Build and start services with production overrides
print_info "Step 8: Building and starting services with protected configuration..."
if docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build; then
    print_status "Services started successfully"
else
    print_error "Failed to start services! Attempting rollback..."
    if [ -f "docker-compose.yml.backup_$TIMESTAMP" ]; then
        cp "docker-compose.yml.backup_$TIMESTAMP" docker-compose.yml
        docker compose up -d
        print_warning "Rolled back to previous configuration"
    fi
    exit 1
fi

# Step 9: Wait for services to be healthy
print_info "Step 9: Waiting for services to become healthy..."
sleep 30

# Step 10: Verify deployment
print_info "Step 10: Verifying deployment..."
if curl -s http://localhost:3000/api/health > /dev/null; then
    print_status "Health check passed - application is responding"
else
    print_warning "Health check failed - application may still be starting"
fi

# Step 11: Show final status
print_info "Step 11: Final status check..."
docker compose -f docker-compose.yml -f docker-compose.production.yml ps

echo
print_status "🎉 Update deployment completed successfully!"
echo
print_info "Application URL: http://172.16.58.224:3000"
print_info "Admin Login: admin@yourdomain.com / Admin123!@#"
echo
print_info "Backup created: $BACKUP_FILE"
print_info "To rollback if needed: ./rollback-config.sh $TIMESTAMP"
echo
