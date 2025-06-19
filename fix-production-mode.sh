#!/bin/bash

echo "=============================================="
echo "GamePlan Production Mode Fix Script"
echo "=============================================="
echo ""

# Check if we're in the right directory
if [ ! -f "app.js" ]; then
    echo "❌ Error: Not in GamePlan directory. Please run this from ~/GamePlan"
    exit 1
fi

echo "📍 Working in directory: $(pwd)"
echo ""

# Backup current configuration
echo "1. CREATING BACKUP"
echo "=============================================="
backup_dir="config-backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup_dir"

if [ -f ".env" ]; then
    cp .env "$backup_dir/"
    echo "✅ Backed up .env to $backup_dir/"
fi

if [ -f "docker-compose.override.yml" ]; then
    cp docker-compose.override.yml "$backup_dir/"
    echo "✅ Backed up docker-compose.override.yml to $backup_dir/"
fi

echo ""

# Fix 1: Remove development override file
echo "2. REMOVING DEVELOPMENT OVERRIDES"
echo "=============================================="
if [ -f "docker-compose.override.yml" ]; then
    echo "⚠️  Found docker-compose.override.yml - this often forces development mode"
    mv docker-compose.override.yml docker-compose.override.yml.disabled
    echo "✅ Disabled docker-compose.override.yml (renamed to .disabled)"
else
    echo "✅ No docker-compose.override.yml found"
fi

echo ""

# Fix 2: Ensure production compose file exists
echo "3. ENSURING PRODUCTION CONFIGURATION"
echo "=============================================="
if [ ! -f "docker-compose.production.yml" ]; then
    if [ -f "docker-compose.production.yml.example" ]; then
        echo "📝 Creating docker-compose.production.yml from example"
        cp docker-compose.production.yml.example docker-compose.production.yml
        echo "✅ Created docker-compose.production.yml"
    else
        echo "❌ No docker-compose.production.yml.example found!"
        echo "   You may need to create this file manually"
    fi
else
    echo "✅ docker-compose.production.yml already exists"
fi

echo ""

# Fix 3: Verify .env file has correct settings
echo "4. VERIFYING ENVIRONMENT CONFIGURATION"
echo "=============================================="
if [ -f ".env" ]; then
    if grep -q "NODE_ENV=production" .env; then
        echo "✅ NODE_ENV=production found in .env"
    else
        echo "⚠️  NODE_ENV not set to production in .env"
        echo "   Current NODE_ENV setting:"
        grep "NODE_ENV" .env || echo "   NODE_ENV not found"
        
        # Ask user if they want to fix it
        read -p "   Do you want to set NODE_ENV=production? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if grep -q "NODE_ENV=" .env; then
                sed -i 's/NODE_ENV=.*/NODE_ENV=production/' .env
                echo "✅ Updated NODE_ENV to production"
            else
                echo "NODE_ENV=production" >> .env
                echo "✅ Added NODE_ENV=production to .env"
            fi
        fi
    fi
    
    if grep -q "AUTO_LOGIN_ADMIN=false" .env; then
        echo "✅ AUTO_LOGIN_ADMIN=false found in .env"
    else
        echo "⚠️  AUTO_LOGIN_ADMIN not set to false"
        echo "   Current AUTO_LOGIN_ADMIN setting:"
        grep "AUTO_LOGIN_ADMIN" .env || echo "   AUTO_LOGIN_ADMIN not found"
        
        read -p "   Do you want to set AUTO_LOGIN_ADMIN=false? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if grep -q "AUTO_LOGIN_ADMIN=" .env; then
                sed -i 's/AUTO_LOGIN_ADMIN=.*/AUTO_LOGIN_ADMIN=false/' .env
                echo "✅ Updated AUTO_LOGIN_ADMIN to false"
            else
                echo "AUTO_LOGIN_ADMIN=false" >> .env
                echo "✅ Added AUTO_LOGIN_ADMIN=false to .env"
            fi
        fi
    fi
else
    echo "❌ .env file not found!"
    if [ -f ".env.example" ]; then
        read -p "   Do you want to create .env from .env.example? (y/n): " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            cp .env.example .env
            echo "✅ Created .env from .env.example"
            echo "⚠️  Please edit .env to configure your specific settings"
        fi
    fi
fi

echo ""

# Fix 4: Restart with production configuration
echo "5. RESTARTING WITH PRODUCTION CONFIGURATION"
echo "=============================================="
echo "Stopping current containers..."
docker compose down

echo ""
echo "Starting with production configuration..."
if [ -f "docker-compose.production.yml" ]; then
    docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
    echo "✅ Started with production configuration"
else
    echo "⚠️  No docker-compose.production.yml found, starting with base configuration"
    docker compose up -d
fi

echo ""

# Fix 5: Verify the fix
echo "6. VERIFICATION"
echo "=============================================="
echo "Waiting for containers to start..."
sleep 10

echo "Container status:"
docker compose ps

echo ""
echo "Checking NODE_ENV in running container:"
if docker compose ps | grep -q "gameplan-app.*Up"; then
    container_node_env=$(docker compose exec gameplan-app env | grep NODE_ENV || echo "NODE_ENV not found")
    echo "$container_node_env"
    
    if echo "$container_node_env" | grep -q "NODE_ENV=production"; then
        echo "✅ SUCCESS: Container is running in production mode!"
    else
        echo "❌ Container is not in production mode"
    fi
else
    echo "❌ gameplan-app container is not running properly"
fi

echo ""
echo "=============================================="
echo "FIX COMPLETE"
echo "=============================================="
echo ""
echo "📋 SUMMARY OF CHANGES:"
echo "- Disabled any docker-compose.override.yml file"
echo "- Ensured docker-compose.production.yml exists"
echo "- Verified .env has NODE_ENV=production"
echo "- Restarted containers with production configuration"
echo ""
echo "🌐 Test your application at: http://your-server-ip:3000"
echo "   - There should be NO development mode banner"
echo "   - Auto-login should be disabled"
echo ""
echo "📁 Backup created in: $backup_dir"
echo "   (You can restore from this if needed)"
