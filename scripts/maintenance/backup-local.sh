#!/bin/bash

# GamePlan Local Development Backup Script
# This script creates backups of your local development environment

set -e

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Configuration
BACKUP_DIR="./local-backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
CONFIG_BACKUP_FILE="${BACKUP_DIR}/config_backup_${TIMESTAMP}.tar.gz"
DB_BACKUP_FILE="${BACKUP_DIR}/database_backup_${TIMESTAMP}"

echo -e "${BLUE}🗄️  GamePlan Local Development Backup${NC}"
echo -e "${BLUE}=====================================${NC}"

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

print_info "Starting local development backup..."

# Backup configuration files
backup_config() {
    print_info "Backing up configuration files..."
    
    local files_to_backup=""
    
    # Check which files exist and add them to backup
    [ -f ".env.local" ] && files_to_backup="$files_to_backup .env.local"
    [ -f "docker-compose.local.yml" ] && files_to_backup="$files_to_backup docker-compose.local.yml"
    [ -f "docker-compose.override.yml" ] && files_to_backup="$files_to_backup docker-compose.override.yml"
    [ -f "docker-compose.yml" ] && files_to_backup="$files_to_backup docker-compose.yml"
    
    if [ -n "$files_to_backup" ]; then
        tar -czf "$CONFIG_BACKUP_FILE" $files_to_backup 2>/dev/null || true
        print_status "Configuration backup created: $CONFIG_BACKUP_FILE"
    else
        print_warning "No configuration files found to backup"
    fi
}

# Backup database
backup_database() {
    print_info "Backing up local database..."
    
    # Check if MongoDB container is running
    if docker compose ps | grep -q "gameplan-mongodb.*Up"; then
        # Load environment variables
        if [ -f ".env.local" ]; then
            export $(grep -v '^#' .env.local | xargs)
        fi
        
        # Create database backup using mongodump
        docker compose exec -T mongodb mongodump \
            --host localhost \
            --port 27017 \
            --username admin \
            --password "${MONGO_ROOT_PASSWORD:-local_dev_root_password}" \
            --authenticationDatabase admin \
            --db gameplan \
            --out /backups/database_backup_${TIMESTAMP} 2>/dev/null || {
            
            print_warning "Direct mongodump failed, trying alternative method..."
            
            # Alternative: use docker run with network
            docker run --rm \
                --network gameplan_gameplan-network \
                -v "${PWD}/local-backups:/backups" \
                mongo:7.0 \
                mongodump \
                --host gameplan-mongodb \
                --port 27017 \
                --username admin \
                --password "${MONGO_ROOT_PASSWORD:-local_dev_root_password}" \
                --authenticationDatabase admin \
                --db gameplan \
                --out /backups/database_backup_${TIMESTAMP} 2>/dev/null || {
                
                print_error "Database backup failed. Make sure MongoDB is running."
                return 1
            }
        }
        
        print_status "Database backup created: ${DB_BACKUP_FILE}"
    else
        print_warning "MongoDB container is not running. Skipping database backup."
        print_info "Start your local environment with: ./setup-local.sh"
    fi
}

# Create backup manifest
create_manifest() {
    print_info "Creating backup manifest..."
    
    local manifest_file="${BACKUP_DIR}/backup_manifest_${TIMESTAMP}.txt"
    
    cat > "$manifest_file" << EOF
GamePlan Local Development Backup Manifest
==========================================
Backup Date: $(date)
Timestamp: ${TIMESTAMP}

Configuration Backup: $(basename "$CONFIG_BACKUP_FILE")
Database Backup: $(basename "$DB_BACKUP_FILE")

Files included in configuration backup:
$(tar -tzf "$CONFIG_BACKUP_FILE" 2>/dev/null || echo "No configuration backup created")

Environment:
- Node.js Version: $(node --version 2>/dev/null || echo "Not available")
- npm Version: $(npm --version 2>/dev/null || echo "Not available")
- Docker Version: $(docker --version 2>/dev/null || echo "Not available")
- Docker Compose Version: $(docker compose version 2>/dev/null || echo "Not available")

Docker Services Status:
$(docker compose ps 2>/dev/null || echo "No services running")

EOF

    print_status "Backup manifest created: $manifest_file"
}

# Show backup summary
show_summary() {
    print_info "Backup Summary:"
    echo
    print_status "Backup completed successfully!"
    echo
    print_info "Backup files created:"
    ls -la "$BACKUP_DIR"/*_${TIMESTAMP}* 2>/dev/null || print_warning "No backup files found"
    echo
    print_info "To restore this backup:"
    echo "  1. Stop current services: docker compose down"
    echo "  2. Restore config: tar -xzf $CONFIG_BACKUP_FILE"
    echo "  3. Restore database: ./restore-local.sh ${TIMESTAMP}"
    echo "  4. Restart services: ./setup-local.sh"
    echo
}

# Main execution
main() {
    backup_config
    backup_database
    create_manifest
    show_summary
}

# Run main function
main "$@"
