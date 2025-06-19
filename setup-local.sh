#!/bin/bash

# GamePlan Local Development Setup Script
# This script sets up a complete local development environment

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
BACKUP_DIR="./local-backups"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

echo -e "${BLUE}🚀 GamePlan Local Development Setup${NC}"
echo -e "${BLUE}====================================${NC}"

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

print_header() {
    echo -e "${PURPLE}🔧 $1${NC}"
}

# Check if Docker is running
check_docker() {
    print_header "Checking Docker availability..."
    if ! docker info > /dev/null 2>&1; then
        print_error "Docker is not running. Please start Docker and try again."
        exit 1
    fi
    print_status "Docker is running"
}

# Check if Docker Compose is available
check_docker_compose() {
    print_header "Checking Docker Compose availability..."
    if ! docker compose version > /dev/null 2>&1; then
        print_error "Docker Compose is not available. Please install Docker Compose and try again."
        exit 1
    fi
    print_status "Docker Compose is available"
}

# Create backup directory
create_backup_dir() {
    print_header "Creating backup directory..."
    mkdir -p "$BACKUP_DIR"
    print_status "Backup directory created: $BACKUP_DIR"
}

# Setup local environment file
setup_env_file() {
    print_header "Setting up local environment file..."
    
    if [ ! -f ".env.local" ]; then
        if [ -f ".env.local.example" ]; then
            cp .env.local.example .env.local
            print_status "Created .env.local from example file"
            print_info "Please review and customize .env.local for your local setup"
        else
            print_warning ".env.local.example not found. Creating basic .env.local"
            cat > .env.local << 'EOF'
# Basic local development configuration
PORT=3000
NODE_ENV=development
MONGO_ROOT_PASSWORD=local_dev_root_password
MONGO_PASSWORD=local_dev_app_password
SESSION_SECRET=local_development_session_secret_not_for_production
ADMIN_EMAIL=admin@localhost.dev
ADMIN_PASSWORD=LocalAdmin123!
ADMIN_NAME=Local Development Admin
ADMIN_NICKNAME=DevAdmin
RAWG_API_KEY=3963501b74354e0688413453cb8c6bc4
MONGO_EXPRESS_PORT=8081
MONGO_EXPRESS_USER=admin
MONGO_EXPRESS_PASSWORD=local_mongo_express_password
LOG_LEVEL=debug
LOG_CONSOLE=true
AUTO_LOGIN_ADMIN=true
EOF
            print_status "Created basic .env.local file"
        fi
    else
        print_status ".env.local already exists"
    fi
}

# Install dependencies
install_dependencies() {
    print_header "Installing Node.js dependencies..."
    
    if [ -f "package.json" ]; then
        if command -v npm > /dev/null 2>&1; then
            npm install
            print_status "Dependencies installed with npm"
        else
            print_warning "npm not found. Please install Node.js and npm"
        fi
    else
        print_warning "package.json not found"
    fi
}

# Build Docker images
build_images() {
    print_header "Building Docker images..."
    
    if [ -f "docker-compose.local.yml" ]; then
        docker compose -f docker-compose.yml -f docker-compose.local.yml build
        print_status "Docker images built successfully"
    else
        print_warning "docker-compose.local.yml not found, using default configuration"
        docker compose build
        print_status "Docker images built with default configuration"
    fi
}

# Start services
start_services() {
    print_header "Starting local development services..."
    
    if [ -f "docker-compose.local.yml" ]; then
        docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
        print_status "Services started with local development configuration"
    else
        docker compose up -d
        print_status "Services started with default configuration"
    fi
}

# Wait for services to be healthy
wait_for_services() {
    print_header "Waiting for services to become healthy..."
    
    local max_attempts=30
    local attempt=1
    
    while [ $attempt -le $max_attempts ]; do
        if docker compose ps | grep -q "healthy"; then
            print_status "Services are healthy"
            return 0
        fi
        
        print_info "Attempt $attempt/$max_attempts - waiting for services..."
        sleep 5
        attempt=$((attempt + 1))
    done
    
    print_warning "Services may still be starting. Check with 'docker compose ps'"
}

# Initialize admin user
init_admin() {
    print_header "Initializing admin user..."
    
    if [ -f "docker-compose.local.yml" ]; then
        docker compose -f docker-compose.yml -f docker-compose.local.yml run --rm init-admin
    else
        docker compose run --rm init-admin
    fi
    
    print_status "Admin user initialization completed"
}

# Show final status
show_status() {
    print_header "Final setup status..."
    
    echo
    print_status "🎉 Local development environment setup complete!"
    echo
    print_info "Application URL: http://localhost:3000"
    print_info "Mongo Express: http://localhost:8081"
    print_info "Admin Login: Check your .env.local file for credentials"
    echo
    print_info "Useful commands:"
    echo "  • View logs: docker compose logs -f"
    echo "  • Stop services: docker compose down"
    echo "  • Restart services: docker compose restart"
    echo "  • Backup database: ./backup-local.sh"
    echo "  • Reset environment: ./reset-local.sh"
    echo
    
    # Show running services
    print_info "Running services:"
    if [ -f "docker-compose.local.yml" ]; then
        docker compose -f docker-compose.yml -f docker-compose.local.yml ps
    else
        docker compose ps
    fi
}

# Main execution
main() {
    print_info "Starting GamePlan local development setup..."
    echo
    
    check_docker
    check_docker_compose
    create_backup_dir
    setup_env_file
    install_dependencies
    build_images
    start_services
    wait_for_services
    init_admin
    show_status
    
    echo
    print_status "Setup completed successfully! 🚀"
}

# Run main function
main "$@"
