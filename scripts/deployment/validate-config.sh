#!/bin/bash

# GamePlan Configuration Validator
# This script validates and fixes common configuration issues

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

echo -e "${BLUE}🔍 GamePlan Configuration Validator${NC}"
echo -e "${BLUE}===================================${NC}"

VALIDATION_ERRORS=0
VALIDATION_WARNINGS=0
AUTO_FIX=${1:-false}

# Check if environment file exists and is valid
validate_env_file() {
    local env_file=$1
    local env_type=$2
    
    print_header "Validating $env_type environment file: $env_file"
    
    if [ ! -f "$env_file" ]; then
        print_error "$env_file not found"
        ((VALIDATION_ERRORS++))
        return 1
    fi
    
    # Check for required variables
    local required_vars=(
        "NODE_ENV"
        "MONGO_URI"
        "SESSION_SECRET"
        "MONGO_ROOT_PASSWORD"
        "MONGO_PASSWORD"
        "ADMIN_EMAIL"
        "ADMIN_PASSWORD"
        "ADMIN_NAME"
    )
    
    local missing_vars=()
    local empty_vars=()
    
    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" "$env_file"; then
            missing_vars+=("$var")
        else
            # Check if variable is empty
            local value=$(grep "^${var}=" "$env_file" | cut -d'=' -f2- | tr -d '"' | tr -d "'")
            if [ -z "$value" ]; then
                empty_vars+=("$var")
            fi
        fi
    done
    
    if [ ${#missing_vars[@]} -gt 0 ]; then
        print_error "Missing required variables in $env_file:"
        for var in "${missing_vars[@]}"; do
            echo "  - $var"
        done
        ((VALIDATION_ERRORS++))
    fi
    
    if [ ${#empty_vars[@]} -gt 0 ]; then
        print_error "Empty required variables in $env_file:"
        for var in "${empty_vars[@]}"; do
            echo "  - $var"
        done
        ((VALIDATION_ERRORS++))
    fi
    
    # Check NODE_ENV value
    if grep -q "^NODE_ENV=" "$env_file"; then
        local node_env=$(grep "^NODE_ENV=" "$env_file" | cut -d'=' -f2 | tr -d '"' | tr -d "'")
        if [ "$env_type" = "production" ] && [ "$node_env" != "production" ]; then
            print_warning "NODE_ENV is '$node_env' but should be 'production' for production environment"
            ((VALIDATION_WARNINGS++))
            
            if [ "$AUTO_FIX" = "true" ]; then
                print_info "Auto-fixing NODE_ENV to 'production'"
                sed -i 's/^NODE_ENV=.*/NODE_ENV=production/' "$env_file"
                print_status "Fixed NODE_ENV in $env_file"
            fi
        fi
    fi
    
    if [ ${#missing_vars[@]} -eq 0 ] && [ ${#empty_vars[@]} -eq 0 ]; then
        print_status "$env_file validation passed"
    fi
}

# Check Docker Compose file for common issues
validate_docker_compose() {
    local compose_file=$1
    local compose_type=$2
    
    print_header "Validating $compose_type Docker Compose file: $compose_file"
    
    if [ ! -f "$compose_file" ]; then
        print_error "$compose_file not found"
        ((VALIDATION_ERRORS++))
        return 1
    fi
    
    # Check for obsolete version field
    if grep -q "^version:" "$compose_file"; then
        print_warning "Obsolete 'version' field found in $compose_file"
        ((VALIDATION_WARNINGS++))
        
        if [ "$AUTO_FIX" = "true" ]; then
            print_info "Auto-removing obsolete version field"
            sed -i '/^version:/d' "$compose_file"
            print_status "Removed obsolete version field from $compose_file"
        fi
    fi
    
    # Check for empty environment variables (the main issue we encountered)
    if [ "$compose_type" = "production" ]; then
        local empty_env_vars=$(grep -n "^\s*-\s*[A-Z_]*=\s*$" "$compose_file" || true)
        if [ -n "$empty_env_vars" ]; then
            print_error "Empty environment variable overrides found in $compose_file:"
            echo "$empty_env_vars"
            print_error "These empty overrides will nullify values from .env.production"
            ((VALIDATION_ERRORS++))
            
            if [ "$AUTO_FIX" = "true" ]; then
                print_info "Auto-removing empty environment variable overrides"
                # Remove lines with empty environment variables
                sed -i '/^\s*-\s*[A-Z_]*=\s*$/d' "$compose_file"
                print_status "Removed empty environment overrides from $compose_file"
            fi
        fi
    fi
    
    # Check for proper env_file reference
    if [ "$compose_type" = "production" ]; then
        if ! grep -q "env_file:" "$compose_file"; then
            print_warning "No env_file reference found in $compose_file"
            ((VALIDATION_WARNINGS++))
        elif ! grep -A1 "env_file:" "$compose_file" | grep -q ".env.production"; then
            print_warning ".env.production not referenced in env_file section"
            ((VALIDATION_WARNINGS++))
        fi
    fi
    
    print_status "$compose_file validation completed"
}

# Validate service connectivity
validate_services() {
    print_header "Validating service configuration"
    
    # Check if Docker is running
    if ! docker info >/dev/null 2>&1; then
        print_error "Docker is not running"
        ((VALIDATION_ERRORS++))
        return 1
    fi
    
    print_status "Docker is running"
    
    # Check if Docker Compose is available
    if ! docker compose version >/dev/null 2>&1; then
        print_error "Docker Compose is not available"
        ((VALIDATION_ERRORS++))
        return 1
    fi
    
    print_status "Docker Compose is available"
}

# Generate missing configuration files
generate_missing_configs() {
    print_header "Checking for missing configuration files"
    
    # Check for production environment file
    if [ ! -f ".env.production" ]; then
        if [ -f ".env.example" ]; then
            print_warning ".env.production missing, but .env.example exists"
            if [ "$AUTO_FIX" = "true" ]; then
                print_info "Creating .env.production from .env.example"
                cp .env.example .env.production
                # Set NODE_ENV to production
                sed -i 's/NODE_ENV=.*/NODE_ENV=production/' .env.production
                print_status "Created .env.production (please customize with your settings)"
                print_warning "IMPORTANT: Update passwords and secrets in .env.production"
            else
                print_info "Run with 'auto-fix' to create .env.production from template"
            fi
        else
            print_error "Both .env.production and .env.example are missing"
            ((VALIDATION_ERRORS++))
        fi
    fi
    
    # Check for production Docker Compose file
    if [ ! -f "docker-compose.production.yml" ]; then
        if [ -f "docker-compose.production.yml.example" ]; then
            print_warning "docker-compose.production.yml missing, but example exists"
            if [ "$AUTO_FIX" = "true" ]; then
                print_info "Creating docker-compose.production.yml from example"
                cp docker-compose.production.yml.example docker-compose.production.yml
                print_status "Created docker-compose.production.yml"
            else
                print_info "Run with 'auto-fix' to create docker-compose.production.yml from template"
            fi
        else
            print_error "Both docker-compose.production.yml and example are missing"
            ((VALIDATION_ERRORS++))
        fi
    fi
}

# Main validation function
main() {
    print_info "Starting configuration validation..."
    if [ "$AUTO_FIX" = "true" ]; then
        print_info "Auto-fix mode enabled - will attempt to fix issues automatically"
    fi
    echo
    
    # Validate services first
    validate_services
    
    # Generate missing configs if needed
    generate_missing_configs
    
    # Validate environment files
    if [ -f ".env.production" ]; then
        validate_env_file ".env.production" "production"
    fi
    
    if [ -f ".env.local" ]; then
        validate_env_file ".env.local" "local"
    fi
    
    # Validate Docker Compose files
    validate_docker_compose "docker-compose.yml" "base"
    
    if [ -f "docker-compose.production.yml" ]; then
        validate_docker_compose "docker-compose.production.yml" "production"
    fi
    
    if [ -f "docker-compose.local.yml" ]; then
        validate_docker_compose "docker-compose.local.yml" "local"
    fi
    
    # Summary
    echo
    print_header "Validation Summary"
    
    if [ $VALIDATION_ERRORS -eq 0 ] && [ $VALIDATION_WARNINGS -eq 0 ]; then
        print_status "🎉 All validations passed! Configuration is healthy."
    else
        if [ $VALIDATION_ERRORS -gt 0 ]; then
            print_error "Found $VALIDATION_ERRORS error(s) that need attention"
        fi
        
        if [ $VALIDATION_WARNINGS -gt 0 ]; then
            print_warning "Found $VALIDATION_WARNINGS warning(s) - consider fixing these"
        fi
        
        if [ "$AUTO_FIX" != "true" ] && [ $VALIDATION_ERRORS -gt 0 ]; then
            echo
            print_info "To automatically fix common issues, run:"
            echo "  ./validate-config.sh auto-fix"
        fi
    fi
    
    echo
    
    # Exit with error code if there are validation errors
    if [ $VALIDATION_ERRORS -gt 0 ]; then
        exit 1
    fi
}

# Run main function
main "$@"
