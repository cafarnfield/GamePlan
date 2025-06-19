#!/bin/bash

# GamePlan Complete Deployment Script - Fixed Version
# This script runs everything in one session to avoid repeated password prompts

set -e

echo "=== GamePlan Complete Deployment Script ==="
echo "Starting deployment at $(date)"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%H:%M:%S')] INFO: $1${NC}"
}

# Phase 1: System Information and Cleanup
log "Phase 1: System Assessment and Cleanup"
echo "System Information:"
uname -a
cat /etc/os-release | grep PRETTY_NAME
free -h | grep Mem
df -h / | tail -1

echo
log "Checking for existing GamePlan installation..."
cd /home/chrisadmin/GamePlan || { error "GamePlan directory not found"; exit 1; }

log "Stopping and removing existing containers..."
docker stop gameplan-app gameplan-mongodb gameplan-init-admin 2>/dev/null || true
docker rm gameplan-app gameplan-mongodb gameplan-init-admin 2>/dev/null || true
docker volume rm gameplan_mongodb_data 2>/dev/null || true

log "Cleaning up Docker system..."
docker system prune -f

echo
log "Phase 1 Complete - System cleaned"

# Phase 2: System Updates and Dependencies
log "Phase 2: System Updates and Dependencies"
echo "H3llfire@gp" | sudo -S apt update
echo "H3llfire@gp" | sudo -S apt install -y openssl curl wget

# Phase 3: Environment Configuration
log "Phase 3: Environment Configuration"
log "Creating fresh environment file..."
cp .env.example .env

log "Generating secure passwords (alphanumeric only)..."
MONGO_ROOT_PASSWORD=$(openssl rand -hex 16)
MONGO_PASSWORD=$(openssl rand -hex 16)
SESSION_SECRET=$(openssl rand -hex 24)
ADMIN_PASSWORD=$(openssl rand -hex 8)
MONGO_EXPRESS_PASSWORD=$(openssl rand -hex 8)

log "Creating new environment file with secure passwords..."
cat > .env << EOF
# =============================================================================
# GAMEPLAN DOCKER CONFIGURATION
# =============================================================================

# -----------------------------------------------------------------------------
# SERVER CONFIGURATION
# -----------------------------------------------------------------------------
PORT=3000
NODE_ENV=production

# -----------------------------------------------------------------------------
# DATABASE CONFIGURATION
# -----------------------------------------------------------------------------
MONGO_ROOT_PASSWORD=$MONGO_ROOT_PASSWORD
MONGO_PASSWORD=$MONGO_PASSWORD

# Enhanced Database Connection Settings
DB_MAX_RETRY_ATTEMPTS=10
DB_RETRY_DELAY=5000
DB_MAX_RETRY_DELAY=60000
DB_CONNECTION_TIMEOUT=30000
DB_SHUTDOWN_TIMEOUT=10000
DB_MAX_POOL_SIZE=20
DB_MIN_POOL_SIZE=5
DB_MAX_IDLE_TIME=30000
DB_SOCKET_TIMEOUT=45000
DB_HEARTBEAT_FREQUENCY=10000
DB_WRITE_CONCERN=majority
DB_READ_CONCERN=majority
DB_READ_PREFERENCE=primary
DB_JOURNAL=true
DB_WRITE_TIMEOUT=10000
DB_COMPRESSION=zstd,zlib
DB_BUFFER_MAX_ENTRIES=0
DB_BUFFER_COMMANDS=true
DB_IP_FAMILY=4
DB_MONITOR_COMMANDS=false
DB_SLOW_QUERY_THRESHOLD=1000
DB_SLOW_REQUEST_THRESHOLD=5000
DB_HEALTH_CHECK_INTERVAL=30000
DB_METRICS_RETENTION=86400000
DB_SSL=false
DB_SSL_VALIDATE=true
DB_SSL_CA=
DB_SSL_CERT=
DB_SSL_KEY=
DB_READ_ONLY_MODE=false

# -----------------------------------------------------------------------------
# SESSION SECURITY
# -----------------------------------------------------------------------------
SESSION_SECRET=$SESSION_SECRET

# -----------------------------------------------------------------------------
# INITIAL ADMIN USER SETUP
# -----------------------------------------------------------------------------
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=$ADMIN_PASSWORD
ADMIN_NAME=GamePlan Administrator
ADMIN_NICKNAME=Admin

# -----------------------------------------------------------------------------
# EXTERNAL API KEYS
# -----------------------------------------------------------------------------
RAWG_API_KEY=3963501b74354e0688413453cb8c6bc4

# -----------------------------------------------------------------------------
# MONGO EXPRESS (DATABASE ADMIN INTERFACE)
# -----------------------------------------------------------------------------
MONGO_EXPRESS_PORT=8081
MONGO_EXPRESS_USER=admin
MONGO_EXPRESS_PASSWORD=$MONGO_EXPRESS_PASSWORD

# -----------------------------------------------------------------------------
# LOGGING CONFIGURATION
# -----------------------------------------------------------------------------
LOG_LEVEL=info
LOG_MAX_SIZE=100m
LOG_MAX_FILES=30d
LOG_DATE_PATTERN=YYYY-MM-DD
LOG_COMPRESS=true
LOG_CONSOLE=false

# -----------------------------------------------------------------------------
# DEVELOPMENT MODE SETTINGS
# -----------------------------------------------------------------------------
AUTO_LOGIN_ADMIN=false
EOF

log "Environment configured with secure passwords"

# Phase 4: GamePlan Deployment
log "Phase 4: GamePlan Deployment"
log "Starting Docker Compose services..."
docker compose up -d

log "Waiting for services to start..."
sleep 30

log "Checking service status..."
docker compose ps

log "Initializing admin user..."
docker compose --profile init up init-admin

# Phase 5: Firewall Configuration
log "Phase 5: Firewall Configuration"
log "Configuring UFW firewall..."
echo "H3llfire@gp" | sudo -S ufw --force reset
echo "H3llfire@gp" | sudo -S ufw default deny incoming
echo "H3llfire@gp" | sudo -S ufw default allow outgoing
echo "H3llfire@gp" | sudo -S ufw allow 22/tcp
echo "H3llfire@gp" | sudo -S ufw allow 3000/tcp
echo "H3llfire@gp" | sudo -S ufw allow 80/tcp
echo "H3llfire@gp" | sudo -S ufw allow 443/tcp
echo "H3llfire@gp" | sudo -S ufw --force enable

# Phase 6: Systemd Service
log "Phase 6: Creating Systemd Service"
cat > /tmp/gameplan.service << EOF
[Unit]
Description=GamePlan Docker Compose Application
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/chrisadmin/GamePlan
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0
User=chrisadmin
Group=chrisadmin

[Install]
WantedBy=multi-user.target
EOF

echo "H3llfire@gp" | sudo -S cp /tmp/gameplan.service /etc/systemd/system/
echo "H3llfire@gp" | sudo -S systemctl daemon-reload
echo "H3llfire@gp" | sudo -S systemctl enable gameplan.service

# Phase 7: Verification
log "Phase 7: Deployment Verification"
sleep 10

log "Checking container status..."
docker compose ps

log "Testing health endpoint..."
curl -s http://localhost:3000/api/health || warn "Health check failed - app may still be starting"

# Get server IP
SERVER_IP="172.16.58.224"

# Save credentials
cat > /home/chrisadmin/gameplan-credentials.txt << EOF
GamePlan Deployment Credentials
Generated on: $(date)

Admin Login:
Email: admin@yourdomain.com
Password: $ADMIN_PASSWORD

Database Admin (Mongo Express):
URL: http://$SERVER_IP:8081
Username: admin
Password: $MONGO_EXPRESS_PASSWORD

Application URLs:
- Main App: http://$SERVER_IP:3000
- Health Check: http://$SERVER_IP:3000/api/health

Important Notes:
- Change the admin email in .env file if needed
- Keep these credentials secure
- Delete this file after noting the passwords
EOF

echo
echo "=========================================="
echo "🎉 GamePlan Deployment Complete! 🎉"
echo "=========================================="
echo
echo "Access Information:"
echo "- Application: http://$SERVER_IP:3000"
echo "- Health Check: http://$SERVER_IP:3000/api/health"
echo "- Database Admin: http://$SERVER_IP:8081"
echo
echo "Admin Credentials:"
echo "- Email: admin@yourdomain.com"
echo "- Password: $ADMIN_PASSWORD"
echo
echo "Credentials saved to: /home/chrisadmin/gameplan-credentials.txt"
echo
echo "Useful Commands:"
echo "- View logs: docker compose logs -f"
echo "- Restart: docker compose restart"
echo "- Stop: docker compose down"
echo "- Status: docker compose ps"
echo
log "Deployment completed successfully at $(date)"
