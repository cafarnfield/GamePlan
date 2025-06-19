#!/bin/bash

# GamePlan Complete Deployment Script
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

log "Generating secure passwords..."
MONGO_ROOT_PASSWORD=$(openssl rand -base64 32)
MONGO_PASSWORD=$(openssl rand -base64 32)
SESSION_SECRET=$(openssl rand -base64 48)
ADMIN_PASSWORD=$(openssl rand -base64 16)
MONGO_EXPRESS_PASSWORD=$(openssl rand -base64 16)

log "Updating environment file..."
sed -i "s/your_secure_root_password_here/$MONGO_ROOT_PASSWORD/" .env
sed -i "s/your_secure_app_password_here/$MONGO_PASSWORD/" .env
sed -i "s/your_very_secure_session_secret_key_change_this_in_production/$SESSION_SECRET/" .env
sed -i "s/your_secure_admin_password/$ADMIN_PASSWORD/" .env
sed -i "s/your_mongo_express_password/$MONGO_EXPRESS_PASSWORD/" .env
sed -i 's/NODE_ENV=development/NODE_ENV=production/' .env

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
SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "172.16.58.224")

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
