#!/bin/bash

# GamePlan Local Development Reset Script
# This script resets your local development environment to a clean state

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

echo -e "${BLUE}🔄 GamePlan Local Development Reset${NC}"
echo -e "${BLUE}===================================${NC}"

# Ask for confirmation
confirm_reset() {
    print_warning "This will completely reset your local development environment!"
    print_info "The following will be removed:"
    echo "  • All Docker containers and volumes"
    echo "  • Local database data"
    echo "  • Docker images (optional)"
    echo "  • Node modules (optional)"
    echo
    print_info "The following will be preserved:"
    echo "  • Your source code"
    echo "  • Configuration files (.env.local, docker-compose.local.yml)"
    echo "  • Backup files in local-backups/"
    echo
    
    read -p "Are you sure you want to continue? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        print_info "Reset cancelled."
        exit 0
    fi
}

# Create backup before reset
create_backup() {
    print_header "Creating backup before reset..."
    
    if [ -f "./backup-local.sh" ]; then
        print_info "Running backup script..."
        ./backup-local.sh
        print_status "Backup completed"
    else
        print_warning "Backup script not found, skipping backup"
    fi
}

# Stop and remove containers
stop_containers() {
    print_header "Stopping and removing containers..."
    
    # Stop services using local config if available
    if [ -f "docker-compose.local.yml" ]; then
        docker compose -f docker-compose.yml -f docker-compose.local.yml down --remove-orphans 2>/dev/null || true
    else
        docker compose down --remove-orphans 2>/dev/null || true
    fi
    
    # Remove any remaining GamePlan containers
    docker ps -a --filter "name=gameplan" --format "{{.Names}}" | xargs -r docker rm -f 2>/dev/null || true
    
    print_status "Containers stopped and removed"
}

# Remove volumes
remove_volumes() {
    print_header "Removing Docker volumes..."
    
    # Remove local development volumes
    docker volume rm gameplan_local_mongodb_data 2>/dev/null || true
    docker volume rm gameplan_mongodb_data 2>/dev/null || true
    
    # Remove any other GamePlan volumes
    docker volume ls --filter "name=gameplan" --format "{{.Name}}" | xargs -r docker volume rm 2>/dev/null || true
    
    print_status "Docker volumes removed"
}

# Remove networks
remove_networks() {
    print_header "Removing Docker networks..."
    
    # Remove GamePlan networks
    docker network ls --filter "name=gameplan" --format "{{.Name}}" | xargs -r docker network rm 2>/dev/null || true
    
    print_status "Docker networks removed"
}

# Optional: Remove Docker images
remove_images() {
    print_info "Do you want to remove Docker images as well? (y/N): "
    read -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_header "Removing Docker images..."
        
        # Remove GamePlan images
        docker images --filter "reference=gameplan*" --format "{{.Repository}}:{{.Tag}}" | xargs -r docker rmi -f 2>/dev/null || true
        
        # Remove dangling images
        docker image prune -f 2>/dev/null || true
        
        print_status "Docker images removed"
    else
        print_info "Keeping Docker images"
    fi
}

# Optional: Remove node_modules
remove_node_modules() {
    print_info "Do you want to remove node_modules directory? (y/N): "
    read -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        print_header "Removing node_modules..."
        
        if [ -d "node_modules" ]; then
            rm -rf node_modules
            print_status "node_modules removed"
        else
            print_info "node_modules directory not found"
        fi
    else
        print_info "Keeping node_modules"
    fi
}

# Clean up temporary files
cleanup_temp_files() {
    print_header "Cleaning up temporary files..."
    
    # Remove log files
    if [ -d "logs" ]; then
        rm -rf logs/*
        print_status "Log files cleared"
    fi
    
    # Remove temporary files
    find . -name "*.tmp" -type f -delete 2>/dev/null || true
    find . -name "*.log" -type f -delete 2>/dev/null || true
    
    print_status "Temporary files cleaned"
}

# Show final status
show_final_status() {
    print_header "Reset completed!"
    echo
    print_status "🎉 Local development environment has been reset"
    echo
    print_info "To set up your environment again:"
    echo "  ./setup-local.sh"
    echo
    print_info "To restore from a backup:"
    echo "  1. List available backups: ls -la local-backups/"
    echo "  2. Restore: ./restore-local.sh [timestamp]"
    echo
    print_info "Current Docker status:"
    echo "  Containers: $(docker ps -a --filter 'name=gameplan' --format '{{.Names}}' | wc -l) GamePlan containers"
    echo "  Volumes: $(docker volume ls --filter 'name=gameplan' --format '{{.Name}}' | wc -l) GamePlan volumes"
    echo "  Images: $(docker images --filter 'reference=gameplan*' --format '{{.Repository}}' | wc -l) GamePlan images"
}

# Main execution
main() {
    confirm_reset
    create_backup
    stop_containers
    remove_volumes
    remove_networks
    remove_images
    remove_node_modules
    cleanup_temp_files
    show_final_status
}

# Run main function
main "$@"
