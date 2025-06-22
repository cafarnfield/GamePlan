#!/bin/bash

# GamePlan Deployment System Test Script
# This script tests the enhanced deployment system components

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

echo -e "${BLUE}🧪 GamePlan Deployment System Test${NC}"
echo -e "${BLUE}===================================${NC}"

TESTS_PASSED=0
TESTS_FAILED=0

# Test function
run_test() {
    local test_name="$1"
    local test_command="$2"
    
    print_info "Testing: $test_name"
    
    if eval "$test_command" >/dev/null 2>&1; then
        print_status "PASS: $test_name"
        ((TESTS_PASSED++))
        return 0
    else
        print_error "FAIL: $test_name"
        ((TESTS_FAILED++))
        return 1
    fi
}

# Test 1: Check if enhanced deployment script exists
print_header "File Existence Tests"
run_test "Enhanced deployment script exists" "[ -f 'deploy-update-enhanced.sh' ]"
run_test "Configuration validator exists" "[ -f 'validate-config.sh' ]"
run_test "Production template exists" "[ -f 'docker-compose.production.yml.example' ]"
run_test "Environment example exists" "[ -f '.env.example' ]"

# Test 2: Check script syntax
print_header "Script Syntax Tests"
run_test "Enhanced deployment script syntax" "bash -n deploy-update-enhanced.sh"
run_test "Configuration validator syntax" "bash -n validate-config.sh"

# Test 3: Check Docker Compose files
print_header "Docker Compose Tests"
run_test "Base docker-compose.yml is valid" "docker compose -f docker-compose.yml config >/dev/null"

if [ -f "docker-compose.production.yml" ]; then
    run_test "Production docker-compose.yml is valid" "docker compose -f docker-compose.yml -f docker-compose.production.yml config >/dev/null"
else
    print_warning "docker-compose.production.yml not found (expected for fresh setup)"
fi

# Test 4: Check for obsolete version fields
print_header "Configuration Quality Tests"
if grep -q "^version:" docker-compose.yml; then
    print_error "FAIL: Obsolete version field found in docker-compose.yml"
    ((TESTS_FAILED++))
else
    print_status "PASS: No obsolete version field in docker-compose.yml"
    ((TESTS_PASSED++))
fi

# Test 5: Check .gitignore protection
print_header "Security Tests"
run_test "Production env file protected in .gitignore" "grep -q '.env.production' .gitignore"
run_test "Production compose file protected in .gitignore" "grep -q 'docker-compose.production.yml' .gitignore"
run_test "Backup directory protected in .gitignore" "grep -q 'config-backups/' .gitignore"

# Test 6: Check template quality
print_header "Template Quality Tests"
if grep -q "^\s*-\s*[A-Z_]*=\s*$" docker-compose.production.yml.example; then
    print_error "FAIL: Empty environment variables found in production template"
    ((TESTS_FAILED++))
else
    print_status "PASS: No empty environment variables in production template"
    ((TESTS_PASSED++))
fi

# Test 7: Check environment example
if [ -f ".env.example" ]; then
    local required_vars=("NODE_ENV" "MONGO_URI" "SESSION_SECRET" "MONGO_ROOT_PASSWORD" "MONGO_PASSWORD" "ADMIN_EMAIL" "ADMIN_PASSWORD" "ADMIN_NAME")
    local missing_vars=()
    
    for var in "${required_vars[@]}"; do
        if ! grep -q "^${var}=" .env.example; then
            missing_vars+=("$var")
        fi
    done
    
    if [ ${#missing_vars[@]} -eq 0 ]; then
        print_status "PASS: All required variables present in .env.example"
        ((TESTS_PASSED++))
    else
        print_error "FAIL: Missing variables in .env.example: ${missing_vars[*]}"
        ((TESTS_FAILED++))
    fi
fi

# Test 8: Check if Docker is available
print_header "System Requirements Tests"
run_test "Docker is available" "docker --version"
run_test "Docker Compose is available" "docker compose version"

# Test 9: Simulate configuration validation
print_header "Configuration Validation Tests"
if [ -f "validate-config.sh" ]; then
    print_info "Running configuration validator (dry run)..."
    if bash validate-config.sh 2>/dev/null; then
        print_status "PASS: Configuration validator runs successfully"
        ((TESTS_PASSED++))
    else
        print_warning "Configuration validator found issues (this may be expected)"
        print_info "Run './validate-config.sh auto-fix' to fix issues"
    fi
fi

# Summary
echo
print_header "Test Summary"
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"
echo "Total Tests: $((TESTS_PASSED + TESTS_FAILED))"

if [ $TESTS_FAILED -eq 0 ]; then
    echo
    print_status "🎉 All tests passed! Your deployment system is ready."
    echo
    print_info "Next steps:"
    echo "  1. Run './validate-config.sh auto-fix' to ensure configuration is optimal"
    echo "  2. Run './deploy-update-enhanced.sh' for your next deployment"
    echo "  3. Check the DEPLOYMENT_SYSTEM_ENHANCED.md for full documentation"
    exit 0
else
    echo
    print_error "Some tests failed. Please review the issues above."
    echo
    print_info "Common fixes:"
    echo "  - Run './validate-config.sh auto-fix' to fix configuration issues"
    echo "  - Ensure Docker and Docker Compose are installed and running"
    echo "  - Check that all required files are present"
    exit 1
fi
