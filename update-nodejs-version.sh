#!/bin/bash

echo "🔄 Updating to Node.js v24.2.0 in Docker containers..."

# Stop running containers
echo "📦 Stopping existing containers..."
docker-compose down

# Remove old images to force rebuild
echo "🗑️  Removing old Docker images..."
docker rmi $(docker images -q gameplan*) 2>/dev/null || echo "No existing GamePlan images to remove"

# Pull the latest Node.js 24.2.0 Alpine image
echo "⬇️  Pulling Node.js 24.2.0 Alpine image..."
docker pull node:24.2.0-alpine

# Build containers without cache
echo "🔨 Building containers without cache..."
docker-compose build --no-cache

# Start the containers
echo "🚀 Starting containers..."
docker-compose up -d

# Wait a moment for containers to start
echo "⏳ Waiting for containers to start..."
sleep 10

# Check Node.js version in the container
echo "✅ Checking Node.js version in container..."
docker exec gameplan-app node --version

echo "🎉 Update complete! Your container should now be running Node.js 24.2.0"
