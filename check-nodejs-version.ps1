#!/usr/bin/env pwsh

Write-Host "🔍 Checking Node.js version in GamePlan container..." -ForegroundColor Cyan

# Check if container is running
$containerStatus = docker ps --filter "name=gameplan-app" --format "table {{.Names}}\t{{.Status}}"

if ($containerStatus -match "gameplan-app") {
    Write-Host "✅ Container is running" -ForegroundColor Green
    
    # Check Node.js version
    Write-Host "`n📋 Node.js version in container:" -ForegroundColor Yellow
    docker exec gameplan-app node --version
    
    # Check npm version
    Write-Host "`n📋 npm version in container:" -ForegroundColor Yellow
    docker exec gameplan-app npm --version
    
    # Check container image info
    Write-Host "`n📋 Container image info:" -ForegroundColor Yellow
    docker inspect gameplan-app --format='{{.Config.Image}}'
    
} else {
    Write-Host "❌ GamePlan container is not running" -ForegroundColor Red
    Write-Host "Run 'docker-compose up -d' to start the container first" -ForegroundColor Yellow
}

Write-Host "`n🐳 Available Node.js images:" -ForegroundColor Cyan
docker images --filter=reference="node:*" --format "table {{.Repository}}:{{.Tag}}\t{{.CreatedAt}}\t{{.Size}}"
