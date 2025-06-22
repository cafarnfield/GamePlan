#!/usr/bin/env pwsh

Write-Host "🔄 Updating to Node.js v24.2.0 in Docker containers..." -ForegroundColor Cyan

# Stop running containers
Write-Host "📦 Stopping existing containers..." -ForegroundColor Yellow
docker-compose down

# Remove old images to force rebuild
Write-Host "🗑️  Removing old Docker images..." -ForegroundColor Yellow
try {
    $images = docker images -q gameplan*
    if ($images) {
        docker rmi $images
    } else {
        Write-Host "No existing GamePlan images to remove" -ForegroundColor Green
    }
} catch {
    Write-Host "No existing GamePlan images to remove" -ForegroundColor Green
}

# Pull the latest Node.js 24.2.0 Alpine image
Write-Host "⬇️  Pulling Node.js 24.2.0 Alpine image..." -ForegroundColor Yellow
docker pull node:24.2.0-alpine

# Build containers without cache
Write-Host "🔨 Building containers without cache..." -ForegroundColor Yellow
docker-compose build --no-cache

# Start the containers
Write-Host "🚀 Starting containers..." -ForegroundColor Yellow
docker-compose up -d

# Wait a moment for containers to start
Write-Host "⏳ Waiting for containers to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Check Node.js version in the container
Write-Host "✅ Checking Node.js version in container..." -ForegroundColor Yellow
docker exec gameplan-app node --version

Write-Host "🎉 Update complete! Your container should now be running Node.js 24.2.0" -ForegroundColor Green
