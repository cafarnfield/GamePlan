#!/bin/bash

# GamePlan Ubuntu Installation Script
# This script automates the installation of GamePlan on Ubuntu Server

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root. Please run as a regular user with sudo privileges."
   exit 1
fi

# Check Ubuntu version
check_ubuntu_version() {
    log "Checking Ubuntu version..."
    
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        if [[ "$ID" != "ubuntu" ]]; then
            error "This script is designed for Ubuntu. Detected OS: $ID"
            exit 1
        fi
        
        case "$VERSION_ID" in
            "22.04"|"20.04"|"24.04")
                log "Ubuntu $VERSION_ID detected - supported version"
                ;;
            "18.04")
                warn "Ubuntu 18.04 detected - limited support"
                ;;
            *)
                warn "Ubuntu $VERSION_ID detected - not tested, proceeding anyway"
                ;;
        esac
    else
        error "Cannot determine OS version"
        exit 1
    fi
}

# Check system requirements
check_requirements() {
    log "Checking system requirements..."
    
    # Check RAM
    RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
    if [[ $RAM_GB -lt 2 ]]; then
        error "Insufficient RAM. Required: 2GB, Available: ${RAM_GB}GB"
        exit 1
    fi
    log "RAM check passed: ${RAM_GB}GB available"
    
    # Check disk space
    DISK_GB=$(df / | awk 'NR==2{print int($4/1024/1024)}')
    if [[ $DISK_GB -lt 20 ]]; then
        error "Insufficient disk space. Required: 20GB, Available: ${DISK_GB}GB"
        exit 1
    fi
    log "Disk space check passed: ${DISK_GB}GB available"
    
    # Check internet connectivity
    if ! ping -c 1 google.com &> /dev/null; then
        error "No internet connectivity detected"
        exit 1
    fi
    log "Internet connectivity check passed"
}

# Update system packages
update_system() {
    log "Updating system packages..."
    sudo apt update
    sudo apt upgrade -y
    
    log "Installing essential packages..."
    sudo apt install -y \
        curl \
        wget \
        git \
        unzip \
        software-properties-common \
        apt-transport-https \
        ca-certificates \
        gnupg \
        lsb-release \
        ufw \
        htop \
        nano \
        openssl
}

# Install Docker
install_docker() {
    log "Installing Docker..."
    
    # Remove old Docker versions
    sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true
    
    # Add Docker's official GPG key
    sudo mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    
    # Add Docker repository
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
      $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Update package index
    sudo apt update
    
    # Install Docker Engine
    sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    
    # Add user to docker group
    sudo usermod -aG docker $USER
    
    # Enable Docker services
    sudo systemctl enable docker
    sudo systemctl enable containerd
    sudo systemctl start docker
    
    log "Docker installation completed"
}

# Verify Docker installation
verify_docker() {
    log "Verifying Docker installation..."
    
    # Test Docker without sudo (may require newgrp or logout/login)
    if docker --version &>/dev/null; then
        log "Docker version: $(docker --version)"
        log "Docker Compose version: $(docker compose version)"
    else
        warn "Docker installed but may require logout/login to use without sudo"
    fi
    
    # Test Docker functionality
    if docker run --rm hello-world &>/dev/null; then
        log "Docker test successful"
    else
        warn "Docker test failed - may require logout/login"
    fi
}

# Clone GamePlan repository
clone_gameplan() {
    log "Cloning GamePlan repository..."
    
    if [[ -d "GamePlan" ]]; then
        warn "GamePlan directory already exists. Removing..."
        rm -rf GamePlan
    fi
    
    git clone https://github.com/cafarnfield/GamePlan.git
    cd GamePlan
    
    log "GamePlan repository cloned successfully"
}

# Configure environment
configure_environment() {
    log "Configuring environment..."
    
    if [[ ! -f ".env.example" ]]; then
        error ".env.example file not found"
        exit 1
    fi
    
    cp .env.example .env
    
    # Generate secure passwords
    MONGO_ROOT_PASSWORD=$(openssl rand -base64 32)
    MONGO_PASSWORD=$(openssl rand -base64 32)
    SESSION_SECRET=$(openssl rand -base64 48)
    ADMIN_PASSWORD=$(openssl rand -base64 16)
    MONGO_EXPRESS_PASSWORD=$(openssl rand -base64 16)
    
    # Update .env file with generated passwords
    sed -i "s/your_secure_root_password_here/$MONGO_ROOT_PASSWORD/" .env
    sed -i "s/your_secure_app_password_here/$MONGO_PASSWORD/" .env
    sed -i "s/your_very_secure_session_secret_key_change_this_in_production/$SESSION_SECRET/" .env
    sed -i "s/your_secure_admin_password/$ADMIN_PASSWORD/" .env
    sed -i "s/your_mongo_express_password/$MONGO_EXPRESS_PASSWORD/" .env
    
    # Set production environment
    sed -i "s/NODE_ENV=development/NODE_ENV=production/" .env
    
    log "Environment configured with secure passwords"
    
    # Save credentials to file
    cat > ~/gameplan-credentials.txt << EOF
GamePlan Installation Credentials
Generated on: $(date)

Admin Login:
Email: admin@yourdomain.com
Password: $ADMIN_PASSWORD

Database Admin (Mongo Express):
URL: http://your-server:8081
Username: admin
Password: $MONGO_EXPRESS_PASSWORD

IMPORTANT: 
- Change the admin email in .env file
- Keep these credentials secure
- Delete this file after noting the passwords
EOF
    
    info "Credentials saved to ~/gameplan-credentials.txt"
}

# Configure firewall
configure_firewall() {
    log "Configuring UFW firewall..."
    
    # Reset firewall
    sudo ufw --force reset
    
    # Set default policies
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    
    # Allow SSH
    sudo ufw allow 22/tcp
    
    # Allow GamePlan
    sudo ufw allow 3000/tcp
    
    # Allow HTTP/HTTPS for reverse proxy
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    
    # Enable firewall
    sudo ufw --force enable
    
    log "Firewall configured successfully"
}

# Deploy GamePlan
deploy_gameplan() {
    log "Deploying GamePlan..."
    
    # Start services
    docker compose up -d
    
    # Wait for services to start
    log "Waiting for services to start..."
    sleep 30
    
    # Initialize admin user
    log "Initializing admin user..."
    docker compose --profile init up init-admin
    
    log "GamePlan deployment completed"
}

# Verify deployment
verify_deployment() {
    log "Verifying deployment..."
    
    # Check container status
    if docker compose ps | grep -q "Up"; then
        log "Containers are running"
    else
        error "Some containers are not running"
        docker compose ps
        exit 1
    fi
    
    # Check health endpoint
    sleep 10
    if curl -s http://localhost:3000/api/health | grep -q "healthy"; then
        log "Health check passed"
    else
        warn "Health check failed - application may still be starting"
    fi
    
    # Get server IP
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || echo "your-server-ip")
    
    log "Deployment verification completed"
    
    # Display success message
    cat << EOF

${GREEN}🎉 GamePlan Installation Completed Successfully! 🎉${NC}

${BLUE}Access Information:${NC}
- Application URL: http://$SERVER_IP:3000
- Local URL: http://localhost:3000
- Health Check: http://$SERVER_IP:3000/api/health

${BLUE}Admin Credentials:${NC}
- Email: admin@yourdomain.com
- Password: (check ~/gameplan-credentials.txt)

${BLUE}Next Steps:${NC}
1. Update admin email in .env file: nano .env
2. Configure domain name (optional)
3. Set up SSL certificate (see UBUNTU_DEPLOYMENT.md)
4. Set up reverse proxy (see UBUNTU_DEPLOYMENT.md)

${BLUE}Useful Commands:${NC}
- View logs: docker compose logs -f
- Restart: docker compose restart
- Stop: docker compose down
- Update: git pull && docker compose down && docker compose up -d

${YELLOW}Important:${NC}
- Credentials saved in ~/gameplan-credentials.txt
- Full documentation in UBUNTU_DEPLOYMENT.md
- For production use, follow security hardening steps

${GREEN}Installation completed in $(pwd)${NC}

EOF
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service..."
    
    sudo tee /etc/systemd/system/gameplan.service > /dev/null << EOF
[Unit]
Description=GamePlan Docker Compose Application
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$(pwd)
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0
User=$USER
Group=$USER

[Install]
WantedBy=multi-user.target
EOF
    
    # Enable service
    sudo systemctl daemon-reload
    sudo systemctl enable gameplan.service
    
    log "Systemd service created and enabled"
}

# Main installation function
main() {
    log "Starting GamePlan Ubuntu installation..."
    
    check_ubuntu_version
    check_requirements
    update_system
    install_docker
    verify_docker
    clone_gameplan
    configure_environment
    configure_firewall
    deploy_gameplan
    create_systemd_service
    verify_deployment
    
    log "GamePlan installation completed successfully!"
}

# Handle script interruption
trap 'error "Installation interrupted"; exit 1' INT TERM

# Run main function
main "$@"
