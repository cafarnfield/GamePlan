#!/bin/bash

# GamePlan Safe Deployment Update Script
# This script safely updates from GitHub without killing the running application
# Includes backup, validation, and automatic rollback capabilities

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

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

print_header() {
    echo -e "${PURPLE}🔧 $1${NC}"
}

echo -e "${BLUE}🚀 GamePlan Safe Deployment Update${NC}"
echo -e "${BLUE}===================================${NC}"

# Configuration
BACKUP_DIR="./deployment-backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/safe_backup_${TIMESTAMP}.tar.gz"
ROLLBACK_AVAILABLE=false
PRE_SYNC_COMMIT=""
APP_WAS_RUNNING=false

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Check if app is currently running
check_app_status() {
    print_header "Checking Application Status"
    
    if docker compose ps | grep -q "gameplan-app.*Up"; then
        APP_WAS_RUNNING=true
        print_status "Application is currently running"
    else
        APP_WAS_RUNNING=false
        print_warning "Application is not currently running"
    fi
}

# Create comprehensive backup
create_safe_backup() {
    print_header "Creating Safe Configuration Backup"
    
    local files_to_backup=()
    
    # Always backup these critical files if they exist
    [ -f ".env" ] && files_to_backup+=(".env")
    [ -f ".env.production" ] && files_to_backup+=(".env.production")
    [ -f "docker-compose.production.yml" ] && files_to_backup+=("docker-compose.production.yml")
    [ -f "docker-compose.override.yml" ] && files_to_backup+=("docker-compose.override.yml")
    [ -f "docker-compose.local.yml" ] && files_to_backup+=("docker-compose.local.yml")
    
    # Backup any custom configuration directories
    [ -d "config-backups" ] && files_to_backup+=("config-backups/")
    [ -d "logs" ] && files_to_backup+=("logs/")
    
    if [ ${#files_to_backup[@]} -gt 0 ]; then
        tar -czf "$BACKUP_FILE" "${files_to_backup[@]}" 2>/dev/null || true
        print_status "Configuration backed up to $BACKUP_FILE"
        ROLLBACK_AVAILABLE=true
        
        # Create detailed backup manifest
        cat > "${BACKUP_DIR}/backup_manifest_${TIMESTAMP}.txt" << EOF
GamePlan Safe Deployment Backup Manifest
========================================
Backup Date: $(date)
Timestamp: $TIMESTAMP
Backup File: $(basename "$BACKUP_FILE")

Pre-Sync Application Status:
$(docker compose ps 2>/dev/null || echo "Docker status unavailable")

Files included in backup:
$(for file in "${files_to_backup[@]}"; do echo "  - $file"; done)

Git Status Before Update:
$(git status --porcelain 2>/dev/null || echo "Git status unavailable")

Current Git Commit:
$(git rev-parse HEAD 2>/dev/null || echo "Git commit unavailable")

Current Git Branch:
$(git branch --show-current 2>/dev/null || echo "Git branch unavailable")

Environment Variables (sanitized):
$(env | grep -E '^(NODE_ENV|PORT)=' || echo "Environment variables unavailable")
EOF
        print_status "Backup manifest created"
    else
        print_warning "No configuration files found to backup"
    fi
}

# Safe git update function
safe_git_update() {
    print_header "Safe Git Repository Update"
    
    # Store current commit for rollback reference
    PRE_SYNC_COMMIT=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
    print_info "Current commit: $PRE_SYNC_COMMIT"
    
    # Check current branch
    local current_branch=$(git branch --show-current 2>/dev/null || echo "unknown")
    print_info "Current branch: $current_branch"
    
    # Stash any local changes to protect them
    local stash_created=false
    if ! git diff --quiet HEAD 2>/dev/null; then
        print_warning "Local changes detected, stashing them for safety"
        git stash push -m "Safe deployment stash - $(date)" 2>/dev/null || true
        stash_created=true
    fi
    
    # Fetch latest changes
    print_info "Fetching latest changes from origin..."
    if ! git fetch origin 2>/dev/null; then
        print_error "Failed to fetch from origin"
        return 1
    fi
    
    # Check if we're behind origin
    local behind_count=$(git rev-list --count HEAD..origin/main 2>/dev/null || echo "0")
    if [ "$behind_count" -gt 0 ]; then
        print_info "Repository is $behind_count commits behind origin/main"
        print_info "Performing safe merge update..."
        
        # Use merge instead of reset to preserve local changes
        if git merge origin/main --no-edit 2>/dev/null; then
            local new_commit=$(git rev-parse HEAD 2>/dev/null || echo "unknown")
            print_status "Successfully updated to commit: $new_commit"
            
            # Show what changed
            if [ "$PRE_SYNC_COMMIT" != "$new_commit" ] && [ "$PRE_SYNC_COMMIT" != "unknown" ]; then
                print_info "Changes applied:"
                git log --oneline "$PRE_SYNC_COMMIT..$new_commit" 2>/dev/null || true
            fi
        else
            print_error "Merge failed - there may be conflicts"
            
            # Restore stashed changes if we created a stash
            if [ "$stash_created" = true ]; then
                print_info "Restoring stashed changes..."
                git stash pop 2>/dev/null || true
            fi
            return 1
        fi
    else
        print_status "Repository is already up to date"
    fi
    
    # Restore stashed changes if we created a stash
    if [ "$stash_created" = true ]; then
        print_info "Restoring stashed changes..."
        git stash pop 2>/dev/null || true
    fi
    
    return 0
}

# Validate environment after update
validate_environment() {
    print_header "Environment Validation"
    
    # Check if critical files exist
    local validation_passed=true
    
    if [ ! -f ".env" ]; then
        print_error "Critical file .env is missing"
        validation_passed=false
    fi
    
    if [ ! -f "docker-compose.yml" ]; then
        print_error "Critical file docker-compose.yml is missing"
        validation_passed=false
    fi
    
    # Check if production compose file exists or can be created
    if [ ! -f "docker-compose.production.yml" ]; then
        if [ -f "docker-compose.production.yml.example" ]; then
            print_warning "Production compose file missing, creating from template"
            cp docker-compose.production.yml.example docker-compose.production.yml
            print_status "Created docker-compose.production.yml from template"
        else
            print_error "No production compose configuration available"
            validation_passed=false
        fi
    fi
    
    # Validate environment file has required variables
    if [ -f ".env" ]; then
        local missing_vars=()
        for var in NODE_ENV PORT MONGO_PASSWORD SESSION_SECRET; do
            if ! grep -q "^${var}=" .env; then
                missing_vars+=("$var")
            fi
        done
        
        if [ ${#missing_vars[@]} -gt 0 ]; then
            print_warning "Missing environment variables: ${missing_vars[*]}"
            print_info "These may be provided by the system or docker-compose"
        fi
    fi
    
    if [ "$validation_passed" = true ]; then
        print_status "Environment validation passed"
        return 0
    else
        print_error "Environment validation failed"
        return 1
    fi
}

# Smart service restart (only if needed)
smart_service_restart() {
    print_header "Smart Service Management"
    
    # Check if we need to restart at all
    local needs_restart=false
    
    # Check if any critical files changed
    if [ "$PRE_SYNC_COMMIT" != "unknown" ]; then
        local changed_files=$(git diff --name-only "$PRE_SYNC_COMMIT" HEAD 2>/dev/null || echo "")
        
        # Files that require restart
        local restart_triggers="package.json package-lock.json Dockerfile docker-compose.yml app.js src/ config/"
        
        for trigger in $restart_triggers; do
            if echo "$changed_files" | grep -q "$trigger"; then
                print_info "Changes detected in $trigger - restart required"
                needs_restart=true
                break
            fi
        done
    else
        # If we can't determine changes, restart to be safe
        needs_restart=true
    fi
    
    if [ "$needs_restart" = true ]; then
        print_info "Performing rolling restart to apply changes..."
        
        # Use rolling restart to minimize downtime
        if [ "$APP_WAS_RUNNING" = true ]; then
            # Build new images first
            print_info "Building updated images..."
            docker compose build --no-cache gameplan-app
            
            # Rolling restart
            print_info "Performing rolling restart..."
            docker compose up -d --no-deps gameplan-app
            
            print_status "Rolling restart completed"
        else
            print_info "Application was not running, starting services..."
            docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
        fi
    else
        print_status "No restart required - application continues running"
    fi
}

# Health verification with timeout
verify_health() {
    print_header "Health Verification"
    
    local max_attempts=24  # 2 minutes with 5-second intervals
    local attempt=1
    local health_url="http://localhost:3000/api/health"
    
    print_info "Verifying application health (max ${max_attempts} attempts)..."
    
    while [ $attempt -le $max_attempts ]; do
        print_info "Health check attempt $attempt/$max_attempts..."
        
        if curl -s --max-time 5 "$health_url" > /dev/null 2>&1; then
            print_status "Application is healthy and responding"
            
            # Additional verification
            local response=$(curl -s --max-time 5 "$health_url" 2>/dev/null || echo "")
            if echo "$response" | grep -q "healthy"; then
                print_status "Health endpoint confirms application is healthy"
                return 0
            fi
        fi
        
        sleep 5
        ((attempt++))
    done
    
    print_error "Health verification failed after $max_attempts attempts"
    return 1
}

# Rollback function
perform_rollback() {
    print_header "Performing Emergency Rollback"
    
    if [ "$ROLLBACK_AVAILABLE" = true ] && [ -f "$BACKUP_FILE" ]; then
        print_info "Rolling back to previous working configuration..."
        
        # Stop current services
        docker compose down 2>/dev/null || true
        
        # Restore backup
        tar -xzf "$BACKUP_FILE" 2>/dev/null || true
        print_status "Configuration restored from backup"
        
        # Reset git to previous commit if possible
        if [ "$PRE_SYNC_COMMIT" != "unknown" ]; then
            print_info "Resetting git to previous commit: $PRE_SYNC_COMMIT"
            git reset --hard "$PRE_SYNC_COMMIT" 2>/dev/null || true
        fi
        
        # Restart services
        if [ "$APP_WAS_RUNNING" = true ]; then
            docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
        fi
        
        print_status "Rollback completed"
        return 0
    else
        print_error "No backup available for rollback"
        return 1
    fi
}

# Main deployment function
main() {
    print_info "Starting safe deployment update process..."
    echo
    
    # Step 1: Check current application status
    check_app_status
    
    # Step 2: Create comprehensive backup
    create_safe_backup
    
    # Step 3: Safe git update
    if ! safe_git_update; then
        print_error "Git update failed!"
        exit 1
    fi
    
    # Step 4: Validate environment
    if ! validate_environment; then
        print_error "Environment validation failed!"
        if [ "$ROLLBACK_AVAILABLE" = true ]; then
            print_info "Attempting rollback..."
            perform_rollback
        fi
        exit 1
    fi
    
    # Step 5: Smart service restart
    smart_service_restart
    
    # Step 6: Verify health
    if ! verify_health; then
        print_error "Health verification failed!"
        print_info "Attempting rollback..."
        if perform_rollback; then
            print_warning "Rolled back to previous working configuration"
            exit 1
        else
            print_error "Rollback failed - manual intervention required"
            exit 1
        fi
    fi
    
    # Step 7: Final status
    print_header "Deployment Status"
    docker compose ps
    
    echo
    print_status "🎉 Safe deployment update completed successfully!"
    echo
    print_info "Application URL: http://localhost:3000"
    print_info "Health Check: http://localhost:3000/api/health"
    echo
    print_info "Backup created: $BACKUP_FILE"
    print_info "To rollback if needed later: tar -xzf $BACKUP_FILE && docker compose restart"
    echo
    
    # Show recent logs
    print_info "Recent application logs:"
    docker compose logs --tail=5 gameplan-app 2>/dev/null || true
}

# Error handling
trap 'print_error "Script failed at line $LINENO. Attempting rollback..."; perform_rollback || true' ERR

# Run main function
main "$@"
