#!/bin/bash

echo "=============================================="
echo "GamePlan Production Mode Diagnostic Script"
echo "=============================================="
echo ""

# Check if we're in the right directory
if [ ! -f "app.js" ]; then
    echo "❌ Error: Not in GamePlan directory. Please run this from ~/GamePlan"
    exit 1
fi

echo "📍 Current directory: $(pwd)"
echo ""

echo "1. ENVIRONMENT FILE ANALYSIS"
echo "=============================================="
if [ -f ".env" ]; then
    echo "✅ .env file found"
    echo "NODE_ENV setting:"
    grep "NODE_ENV" .env || echo "❌ NODE_ENV not found in .env"
    echo ""
    echo "AUTO_LOGIN_ADMIN setting:"
    grep "AUTO_LOGIN_ADMIN" .env || echo "❌ AUTO_LOGIN_ADMIN not found in .env"
    echo ""
else
    echo "❌ .env file not found!"
fi

echo ""
echo "2. DOCKER COMPOSE FILE ANALYSIS"
echo "=============================================="

# Check for override files that could force development mode
echo "Checking for override files:"
if [ -f "docker-compose.override.yml" ]; then
    echo "⚠️  docker-compose.override.yml FOUND - This may force development mode!"
    echo "Contents:"
    cat docker-compose.override.yml
    echo ""
else
    echo "✅ No docker-compose.override.yml found"
fi

if [ -f "docker-compose.development.yml" ]; then
    echo "📝 docker-compose.development.yml found (this is OK if not being used)"
else
    echo "✅ No docker-compose.development.yml found"
fi

if [ -f "docker-compose.production.yml" ]; then
    echo "✅ docker-compose.production.yml found"
else
    echo "❌ docker-compose.production.yml NOT found - this may be the issue!"
fi

echo ""
echo "3. RUNNING CONTAINER ANALYSIS"
echo "=============================================="

# Check if containers are running
echo "Docker containers status:"
docker compose ps

echo ""
echo "Environment variables in running container:"
if docker compose ps | grep -q "gameplan-app"; then
    echo "NODE_ENV in container:"
    docker compose exec gameplan-app env | grep NODE_ENV || echo "❌ NODE_ENV not set in container"
    
    echo ""
    echo "All environment variables containing 'NODE' or 'DEV':"
    docker compose exec gameplan-app env | grep -i -E "(node|dev|auto_login)" || echo "No relevant environment variables found"
else
    echo "❌ gameplan-app container not running"
fi

echo ""
echo "4. SYSTEM ENVIRONMENT CHECK"
echo "=============================================="
echo "System NODE_ENV (if set):"
echo $NODE_ENV

echo ""
echo "5. DOCKER COMPOSE CONFIGURATION CHECK"
echo "=============================================="
echo "Active Docker Compose configuration:"
docker compose config --services 2>/dev/null || echo "❌ Error reading compose configuration"

echo ""
echo "Environment section from compose config:"
docker compose config 2>/dev/null | grep -A 10 -B 5 "NODE_ENV" || echo "NODE_ENV not found in compose config"

echo ""
echo "6. APPLICATION LOG CHECK"
echo "=============================================="
echo "Recent application logs (looking for environment mode):"
docker compose logs gameplan-app --tail=50 2>/dev/null | grep -i -E "(development|production|node_env|environment)" || echo "No environment-related logs found"

echo ""
echo "7. WEB INTERFACE CHECK"
echo "=============================================="
echo "Checking if development banner is visible (requires curl):"
if command -v curl >/dev/null 2>&1; then
    response=$(curl -s http://localhost:3000 2>/dev/null || curl -s http://127.0.0.1:3000 2>/dev/null)
    if echo "$response" | grep -q -i "development"; then
        echo "⚠️  DEVELOPMENT MODE DETECTED - Found development indicators in web response"
    else
        echo "✅ No development mode indicators found in web response"
    fi
else
    echo "📝 curl not available - cannot check web interface"
fi

echo ""
echo "=============================================="
echo "DIAGNOSTIC COMPLETE"
echo "=============================================="
echo ""
echo "🔍 SUMMARY:"
echo "- Check for ⚠️  warnings above"
echo "- Look for ❌ errors that need fixing"
echo "- Pay special attention to docker-compose.override.yml"
echo "- Verify NODE_ENV is set correctly in both .env and container"
echo ""
echo "Next steps: Share this output to get specific fix recommendations!"
