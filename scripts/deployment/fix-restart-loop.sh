#!/bin/bash

# GamePlan Restart Loop Fix Script
# This script fixes the log directory permission issue causing container restarts

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🔧 GamePlan Restart Loop Fix${NC}"
echo -e "${BLUE}==============================${NC}"
echo ""

# Check if we're in the GamePlan directory
if [[ ! -f "docker-compose.yml" ]]; then
    echo -e "${RED}❌ Error: docker-compose.yml not found${NC}"
    echo -e "${YELLOW}Please run this script from the GamePlan directory${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Found GamePlan directory${NC}"

# Check if Docker is running
if ! docker --version &>/dev/null; then
    echo -e "${RED}❌ Error: Docker not found or not running${NC}"
    echo -e "${YELLOW}Please ensure Docker is installed and running${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker is available${NC}"

# Stop the containers
echo -e "${BLUE}🛑 Stopping containers...${NC}"
docker compose down

# Check if containers are stopped
if docker compose ps | grep -q "Up"; then
    echo -e "${YELLOW}⚠️  Some containers are still running, forcing stop...${NC}"
    docker compose kill
    docker compose down
fi

echo -e "${GREEN}✅ Containers stopped${NC}"

# Rebuild the containers with the log directory fix
echo -e "${BLUE}🔨 Rebuilding containers with log directory fix...${NC}"
docker compose build --no-cache gameplan-app

echo -e "${GREEN}✅ Container rebuilt${NC}"

# Start the containers
echo -e "${BLUE}🚀 Starting containers...${NC}"
docker compose up -d

# Wait for containers to start
echo -e "${BLUE}⏳ Waiting for containers to start...${NC}"
sleep 10

# Check container status
echo -e "${BLUE}📊 Checking container status...${NC}"
docker compose ps

# Check if gameplan-app is running without restarts
APP_STATUS=$(docker compose ps gameplan-app --format "table {{.State}}")
if echo "$APP_STATUS" | grep -q "Up"; then
    echo -e "${GREEN}✅ gameplan-app is running successfully!${NC}"
else
    echo -e "${RED}❌ gameplan-app is not running properly${NC}"
    echo -e "${YELLOW}Checking logs...${NC}"
    docker compose logs --tail=20 gameplan-app
    exit 1
fi

# Check for restart count
RESTART_COUNT=$(docker compose ps gameplan-app --format "table {{.Status}}" | grep -o "Restarting" | wc -l || echo "0")
if [[ $RESTART_COUNT -eq 0 ]]; then
    echo -e "${GREEN}✅ No restarts detected${NC}"
else
    echo -e "${YELLOW}⚠️  Container has restarted $RESTART_COUNT times${NC}"
fi

# Test the health endpoint
echo -e "${BLUE}🏥 Testing health endpoint...${NC}"
sleep 5
if curl -s http://localhost:3000/api/health | grep -q "healthy"; then
    echo -e "${GREEN}✅ Health check passed${NC}"
else
    echo -e "${YELLOW}⚠️  Health check failed - application may still be starting${NC}"
fi

# Check logs for permission errors
echo -e "${BLUE}🔍 Checking for permission errors...${NC}"
if docker compose logs gameplan-app | grep -q "EACCES.*mkdir.*logs"; then
    echo -e "${RED}❌ Permission errors still present in logs${NC}"
    echo -e "${YELLOW}Showing recent logs:${NC}"
    docker compose logs --tail=10 gameplan-app
    exit 1
else
    echo -e "${GREEN}✅ No permission errors found${NC}"
fi

# Final status check
echo ""
echo -e "${GREEN}🎉 Fix Applied Successfully!${NC}"
echo -e "${GREEN}=========================${NC}"
echo ""
echo -e "${BLUE}📊 Current Status:${NC}"
docker compose ps

echo ""
echo -e "${BLUE}🌐 Access Information:${NC}"
echo -e "• Application: ${YELLOW}http://localhost:3000${NC}"
echo -e "• Health Check: ${YELLOW}http://localhost:3000/api/health${NC}"

echo ""
echo -e "${BLUE}📝 Useful Commands:${NC}"
echo -e "• View logs: ${YELLOW}docker compose logs -f gameplan-app${NC}"
echo -e "• Check status: ${YELLOW}docker compose ps${NC}"
echo -e "• Restart if needed: ${YELLOW}docker compose restart${NC}"

echo ""
echo -e "${GREEN}✅ GamePlan should now be running without restart loops!${NC}"
