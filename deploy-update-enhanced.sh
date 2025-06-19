#!/bin/bash

# GamePlan Enhanced Safe Deployment Update Script
# This script safely updates the GamePlan application from GitHub
# with pre-flight validation, automatic configuration healing, and rollback capability

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

echo -e "${BLUE}🚀 GamePlan Enhanced Safe Deployment Update${NC}"
echo -e "${BLUE}===========================================${NC}"

# Configuration
BACKUP_DIR="./config-backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="${BACKUP_DIR}/config_backup_${TIMESTAMP}.tar.gz"
ROLLBACK_AVAILABLE=false
VALIDATION_PASSED=false

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

# Pre-flight validation function
run_preflight_validation() {
    print_header "Pre-flight Configuration Validation"
    
    # Check if validation script exists
    if [ ! -f "./validate-config.sh" ]; then
        print_warning "Configuration validator not found, skipping pre-flight checks"
        return 0
    fi
    
    # Make validation script executable
    chmod +x ./validate-config.sh
    
    # Run validation with auto-fix
    print_info "Running configuration validation with auto-fix..."
    if ./validate-config.sh auto-fix; then
        print_status "Pre-flight validation passed"
        VALIDATION_PASSED=true
        return 0
    else
        print_error "Pre-flight validation failed"
        print_info "Attempting to continue with manual fixes..."
        return 1
    fi
}

# Enhanced backup function
create_enhanced_backup() {
    print_header "Creating Enhanced Configuration Backup"
    
    local files_to_backup=()
    
    # Check which files exist and add them to backup
    [ -f ".env.production" ] && files_to_backup+=(".env.production")
    [ -f "docker-compose.production.yml" ] && files_to_backup+=("docker-compose.production.yml")
    [ -f "docker-compose.yml" ] && files_to_backup+=("docker-compose.yml")
    [ -f ".env" ] && files_to_backup+=(".env")
    
    if [ ${#files_to_backup[@]} -gt 0 ]; then
        tar -czf "$BACKUP_FILE" "${files_to_backup[@]}" 2>/dev/null || true
        print_status "Configuration backed up to $BACKUP_FILE"
        ROLLBACK_AVAILABLE=true
        
        # Create backup manifest
        cat > "${BACKUP_DIR}/backup_manifest_${TIMESTAMP}.txt" << EOF
GamePlan Deployment Backup Manifest
===================================
Backup Date: $(date)
Timestamp: $TIMESTAMP
Backup File: $(basename "$BACKUP_FILE")

Files included in backup:
$(for file in "${files_to_backup[@]}"; do echo "  - $file"; done)

Git Status Before Update:
$(git status --porcelain || echo "Git status unavailable")

Git Commit Before Update:
$(git rev-parse HEAD || echo "Git commit unavailable")

Docker Services Status Before Update:
$(docker compose ps 2>/dev/null || echo "Docker services status unavailable")
EOF
        print_status "Backup manifest created"
    else
        print_warning "No configuration files found to backup"
    fi
}

# Configuration healing function
heal_configuration() {
    print_header "Configuration Healing and Validation"
    
    local healing_performed=false
    
    # Check and fix NODE_ENV in production file
    if [ -f ".env.production" ]; then
        local current_node_env=$(grep "^NODE_ENV=" .env.production | cut -d'=' -f2 | tr -d '"' | tr -d "'" || echo "")
        if [ "$current_node_env" != "production" ]; then
            print_warning "NODE_ENV is '$current_node_env', fixing to 'production'"
            sed -i 's/^NODE_ENV=.*/NODE_ENV=production/' .env.production
            print_status "Fixed NODE_ENV in .env.production"
            healing_performed=true
        fi
    fi
    
    # Check for and fix empty environment variables in docker-compose.production.yml
    if [ -f "docker-compose.production.yml" ]; then
        local empty_vars=$(grep -n "^\s*-\s*[A-Z_]*=\s*$" docker-compose.production.yml || true)
        if [ -n "$empty_vars" ]; then
            print_warning "Found empty environment variable overrides, removing them"
            sed -i '/^\s*-\s*[A-Z_]*=\s*$/d' docker-compose.production.yml
            print_status "Removed empty environment overrides"
            healing_performed=true
        fi
    fi
    
    # Remove obsolete version fields
    for compose_file in docker-compose.yml docker-compose.production.yml docker-compose.local.yml; do
        if [ -f "$compose_file" ] && grep -q "^version:" "$compose_file"; then
            print_warning "Removing obsolete version field from $compose_file"
            sed -i '/^version:/d' "$compose_file"
            print_status "Fixed $compose_file"
            healing_performed=true
        fi
    done
    
    if [ "$healing_performed" = true ]; then
        print_status "Configuration healing completed"
    else
        print_status "No configuration healing needed"
    fi
}

# Enhanced service management
manage_services() {
    local action=$1
    print_header "Service Management: $action"
    
    case $action in
        "stop")
            if docker compose ps | grep -q "Up"; then
                print_info "Stopping services gracefully..."
                docker compose down
                print_status "Services stopped"
            else
                print_info "Services are not running"
            fi
            ;;
        "start")
            print_info "Starting services with production configuration..."
            if [ -f "docker-compose.production.yml" ]; then
                docker compose -f docker-compose.yml -f docker-compose.production.yml up -d --build
            else
                print_warning "Production configuration not found, using default"
                docker compose up -d --build
            fi
            print_status "Services started"
            ;;
        "restart")
            manage_services "stop"
            sleep 5
            manage_services "start"
            ;;
    esac
}

# Enhanced health verification
verify_deployment() {
    print_header "Deployment Verification"
    
    local max_attempts=12
    local attempt=1
    local health_url="http://localhost:3000/api/health"
    local version_url="http://localhost:3000/api/version"
    
    print_info "Waiting for services to become healthy (max ${max_attempts} attempts)..."
    
    while [ $attempt -le $max_attempts ]; do
        print_info "Health check attempt $attempt/$max_attempts..."
        
        # Check if the health endpoint responds
        if curl -s --max-time 10 "$health_url" > /dev/null 2>&1; then
            print_status "Health endpoint is responding"
            
            # Check if the version endpoint responds (proves update worked)
            if curl -s --max-time 10 "$version_url" > /dev/null 2>&1; then
                print_status "Version endpoint is responding - update successful!"
                
                # Show version info
                local version_info=$(curl -s --max-time 10 "$version_url" | jq -r '.message // "Version info available"' 2>/dev/null || echo "Version endpoint working")
                print_info "Version info: $version_info"
                
                return 0
            else
                print_warning "Version endpoint not responding yet..."
            fi
        else
            print_warning "Health endpoint not responding yet..."
        fi
        
        sleep 10
        ((attempt++))
    done
    
    print_error "Health verification failed after $max_attempts attempts"
    return 1
}

# Rollback function
perform_rollback() {
    print_header "Performing Rollback"
    
    if [ "$ROLLBACK_AVAILABLE" = true ] && [ -f "$BACKUP_FILE" ]; then
        print_info "Rolling back to previous configuration..."
        
        # Stop current services
        docker compose down 2>/dev/null || true
        
        # Restore backup
        tar -xzf "$BACKUP_FILE" 2>/dev/null || true
        print_status "Configuration restored from backup"
        
        # Restart services
        manage_services "start"
        
        print_status "Rollback completed"
        return 0
    else
        print_error "No backup available for rollback"
        return 1
    fi
}

# Main deployment function
main() {
    print_info "Starting enhanced safe update process..."
    echo
    
    # Step 1: Pre-flight validation
    if ! run_preflight_validation; then
        print_warning "Pre-flight validation had issues, but continuing..."
    fi
    
    # Step 2: Create enhanced backup
    create_enhanced_backup
    
    # Step 3: Configuration healing
    heal_configuration
    
    # Step 4: Stop services
    manage_services "stop"
    
    # Step 5: Pull latest changes
    print_header "Pulling Latest Changes from Git"
    if git pull origin main; then
        print_status "Git pull completed successfully"
    else
        print_error "Git pull failed!"
        if [ "$ROLLBACK_AVAILABLE" = true ]; then
            print_info "Attempting rollback..."
            perform_rollback
        fi
        exit 1
    fi
    
    # Step 6: Post-update configuration healing
    heal_configuration
    
    # Step 7: Update .gitignore protection
    print_header "Updating Git Protection"
    local gitignore_updated=false
    for protected_file in ".env.production" "docker-compose.production.yml" "config-backups/" ".env.local" "docker-compose.local.yml" "local-backups/"; do
        if ! grep -q "^${protected_file}$" .gitignore 2>/dev/null; then
            echo "$protected_file" >> .gitignore
            gitignore_updated=true
        fi
    done
    
    if [ "$gitignore_updated" = true ]; then
        print_status "Git protection updated"
    else
        print_status "Git protection already configured"
    fi
    
    # Step 8: Start services
    manage_services "start"
    
    # Step 9: Verify deployment
    if verify_deployment; then
        print_status "Deployment verification passed"
    else
        print_error "Deployment verification failed"
        print_info "Attempting rollback..."
        if perform_rollback; then
            print_warning "Rolled back to previous working configuration"
            exit 1
        else
            print_error "Rollback failed - manual intervention required"
            exit 1
        fi
    fi
    
    # Step 10: Final status
    print_header "Final Status"
    docker compose ps
    
    echo
    print_status "🎉 Enhanced deployment update completed successfully!"
    echo
    print_info "Application URL: http://172.16.58.224:3000"
    print_info "Health Check: http://172.16.58.224:3000/api/health"
    print_info "Version Info: http://172.16.58.224:3000/api/version"
    echo
    print_info "Backup created: $BACKUP_FILE"
    print_info "To rollback if needed: tar -xzf $BACKUP_FILE && docker compose restart"
    echo
    
    # Show recent logs
    print_info "Recent application logs:"
    docker compose logs --tail=10 gameplan-app || true
}

# Error handling
trap 'print_error "Script failed at line $LINENO. Exit code: $?"' ERR

# Run main function
main "$@"
