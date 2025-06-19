# GamePlan Ubuntu Server Deployment Guide

Complete step-by-step guide for deploying GamePlan on Ubuntu Server with Docker Compose.

## 🚀 Quick Start (5 Minutes)

For experienced users who want to deploy immediately:

```bash
# 1. Install Docker (if not already installed)
curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh
sudo usermod -aG docker $USER && newgrp docker

# 2. Clone and deploy
git clone https://github.com/cafarnfield/GamePlan.git
cd GamePlan
cp .env.example .env

# 3. Configure environment (edit .env with your settings)
nano .env

# 4. Deploy
docker-compose up -d
docker-compose --profile init up init-admin

# 5. Configure firewall
sudo ufw allow 22 && sudo ufw allow 3000 && sudo ufw --force enable

# 6. Verify deployment
curl http://localhost:3000/api/health
```

**Your GamePlan application is now running at `http://your-server-ip:3000`**

---

## 📋 Prerequisites

### System Requirements
- **OS**: Ubuntu Server 22.04 LTS (recommended) or 20.04 LTS
- **RAM**: Minimum 2GB, Recommended 4GB
- **Storage**: Minimum 20GB free space, Recommended 40GB
- **Network**: Internet connection for package downloads
- **Access**: Root or sudo privileges

### Supported Ubuntu Versions
- ✅ Ubuntu 22.04 LTS (Jammy Jellyfish) - **Recommended**
- ✅ Ubuntu 20.04 LTS (Focal Fossa)
- ✅ Ubuntu 24.04 LTS (Noble Numbat)
- ⚠️ Ubuntu 18.04 LTS (Bionic Beaver) - Limited support

---

## 🔧 Step 1: System Preparation

### Update System Packages
```bash
# Update package lists and upgrade system
sudo apt update && sudo apt upgrade -y

# Install essential packages
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
    nano
```

### Create Application User (Optional but Recommended)
```bash
# Create dedicated user for GamePlan
sudo adduser gameplan
sudo usermod -aG sudo gameplan

# Switch to gameplan user
sudo su - gameplan
```

### Configure System Limits
```bash
# Increase file descriptor limits for Docker
echo "* soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "root soft nofile 65536" | sudo tee -a /etc/security/limits.conf
echo "root hard nofile 65536" | sudo tee -a /etc/security/limits.conf
```

---

## 🐳 Step 2: Docker Installation

### Install Docker Engine
```bash
# Remove old Docker versions (if any)
sudo apt remove -y docker docker-engine docker.io containerd runc

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# Update package index
sudo apt update

# Install Docker Engine, containerd, and Docker Compose
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### Configure Docker
```bash
# Add current user to docker group
sudo usermod -aG docker $USER

# Apply group membership (or logout/login)
newgrp docker

# Enable Docker to start on boot
sudo systemctl enable docker
sudo systemctl enable containerd

# Start Docker service
sudo systemctl start docker
```

### Verify Docker Installation
```bash
# Check Docker version
docker --version
docker compose version

# Test Docker installation
docker run hello-world

# Check Docker service status
sudo systemctl status docker
```

**Expected output:**
```
Docker version 24.0.x, build xxxxx
Docker Compose version v2.x.x
```

---

## 📦 Step 3: GamePlan Deployment

### Clone Repository
```bash
# Clone GamePlan repository
git clone https://github.com/cafarnfield/GamePlan.git
cd GamePlan

# Verify repository contents
ls -la
```

### Configure Environment
```bash
# Copy environment template
cp .env.example .env

# Edit environment configuration
nano .env
```

### Essential Environment Variables
Edit `.env` file with these **required** settings:

```bash
# =============================================================================
# ESSENTIAL CONFIGURATION - CHANGE THESE VALUES
# =============================================================================

# Database passwords (generate secure passwords)
MONGO_ROOT_PASSWORD=your_secure_root_password_here_change_this
MONGO_PASSWORD=your_secure_app_password_here_change_this

# Session security (generate a random 32+ character string)
SESSION_SECRET=your_very_secure_session_secret_key_change_this_in_production

# Initial admin user
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=your_secure_admin_password_change_this
ADMIN_NAME=GamePlan Administrator
ADMIN_NICKNAME=Admin

# Mongo Express (database admin interface)
MONGO_EXPRESS_PASSWORD=your_mongo_express_password_change_this

# =============================================================================
# OPTIONAL CONFIGURATION
# =============================================================================

# Server configuration
PORT=3000
NODE_ENV=production

# API Keys (optional - defaults provided)
RAWG_API_KEY=3963501b74354e0688413453cb8c6bc4

# Logging
LOG_LEVEL=info
LOG_CONSOLE=false
```

### Generate Secure Passwords
```bash
# Generate secure passwords (run these commands and use output in .env)
echo "MONGO_ROOT_PASSWORD=$(openssl rand -base64 32)"
echo "MONGO_PASSWORD=$(openssl rand -base64 32)"
echo "SESSION_SECRET=$(openssl rand -base64 48)"
echo "ADMIN_PASSWORD=$(openssl rand -base64 16)"
echo "MONGO_EXPRESS_PASSWORD=$(openssl rand -base64 16)"
```

### Deploy Application
```bash
# Start all services
docker-compose up -d

# Check deployment status
docker-compose ps

# View logs
docker-compose logs -f gameplan-app
```

### Initialize Admin User
```bash
# Create initial admin user
docker-compose --profile init up init-admin

# Verify admin creation
docker-compose logs init-admin
```

### Verify Deployment
```bash
# Check application health
curl http://localhost:3000/api/health

# Check if application is responding
curl -I http://localhost:3000

# View running containers
docker ps
```

**Expected output:**
```json
{
  "status": "healthy",
  "timestamp": "2023-12-01T10:30:00.000Z",
  "uptime": 60,
  "environment": "production"
}
```

---

## 🔒 Step 4: System Security Configuration

### Configure UFW Firewall
```bash
# Reset firewall to defaults
sudo ufw --force reset

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH (adjust port if needed)
sudo ufw allow 22/tcp

# Allow GamePlan application
sudo ufw allow 3000/tcp

# Allow HTTP and HTTPS (for reverse proxy)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw --force enable

# Check firewall status
sudo ufw status verbose
```

### Secure SSH Configuration (Recommended)
```bash
# Backup SSH config
sudo cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup

# Edit SSH configuration
sudo nano /etc/ssh/sshd_config
```

Add these security settings:
```bash
# Disable root login
PermitRootLogin no

# Use key-based authentication
PasswordAuthentication no
PubkeyAuthentication yes

# Limit login attempts
MaxAuthTries 3
MaxStartups 3

# Disable empty passwords
PermitEmptyPasswords no
```

```bash
# Restart SSH service
sudo systemctl restart sshd
```

---

## 🔄 Step 5: System Service Configuration

### Create Systemd Service
```bash
# Create service file
sudo nano /etc/systemd/system/gameplan.service
```

Add this content:
```ini
[Unit]
Description=GamePlan Docker Compose Application
Requires=docker.service
After=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=/home/gameplan/GamePlan
ExecStart=/usr/bin/docker compose up -d
ExecStop=/usr/bin/docker compose down
TimeoutStartSec=0
User=gameplan
Group=gameplan

[Install]
WantedBy=multi-user.target
```

### Enable Auto-Start
```bash
# Reload systemd
sudo systemctl daemon-reload

# Enable GamePlan service
sudo systemctl enable gameplan.service

# Start service
sudo systemctl start gameplan.service

# Check service status
sudo systemctl status gameplan.service
```

---

## 🌐 Step 6: Reverse Proxy Setup (Production)

### Install Nginx
```bash
# Install Nginx
sudo apt install -y nginx

# Start and enable Nginx
sudo systemctl start nginx
sudo systemctl enable nginx
```

### Configure Nginx for GamePlan
```bash
# Create Nginx configuration
sudo nano /etc/nginx/sites-available/gameplan
```

Add this configuration:
```nginx
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    # Proxy to GamePlan
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        proxy_read_timeout 86400;
    }

    # Health check endpoint
    location /api/health {
        proxy_pass http://localhost:3000/api/health;
        access_log off;
    }

    # Static files caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        proxy_pass http://localhost:3000;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
```

### Enable Nginx Configuration
```bash
# Enable site
sudo ln -s /etc/nginx/sites-available/gameplan /etc/nginx/sites-enabled/

# Remove default site
sudo rm /etc/nginx/sites-enabled/default

# Test Nginx configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx

# Update firewall for Nginx
sudo ufw delete allow 3000/tcp
sudo ufw allow 'Nginx Full'
```

---

## 🔐 Step 7: SSL Certificate Setup

### Install Certbot
```bash
# Install Certbot
sudo apt install -y certbot python3-certbot-nginx

# Obtain SSL certificate (replace with your domain)
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Test automatic renewal
sudo certbot renew --dry-run
```

### Configure Auto-Renewal
```bash
# Add cron job for certificate renewal
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -
```

---

## 📊 Step 8: Monitoring and Maintenance

### Setup Log Monitoring
```bash
# View application logs
docker-compose logs -f gameplan-app

# View system logs
sudo journalctl -u gameplan.service -f

# View Nginx logs
sudo tail -f /var/log/nginx/access.log
sudo tail -f /var/log/nginx/error.log
```

### Health Monitoring Script
```bash
# Create health check script
nano ~/check-gameplan-health.sh
```

Add this content:
```bash
#!/bin/bash
HEALTH_URL="http://localhost:3000/api/health"
RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" $HEALTH_URL)

if [ $RESPONSE -eq 200 ]; then
    echo "$(date): GamePlan is healthy"
else
    echo "$(date): GamePlan health check failed (HTTP $RESPONSE)"
    # Restart service if unhealthy
    sudo systemctl restart gameplan.service
fi
```

```bash
# Make executable
chmod +x ~/check-gameplan-health.sh

# Add to crontab (check every 5 minutes)
echo "*/5 * * * * /home/gameplan/check-gameplan-health.sh >> /home/gameplan/health.log 2>&1" | crontab -
```

### Backup Configuration
```bash
# Create backup script
nano ~/backup-gameplan.sh
```

Add this content:
```bash
#!/bin/bash
BACKUP_DIR="/home/gameplan/backups"
DATE=$(date +%Y%m%d_%H%M%S)

# Create backup directory
mkdir -p $BACKUP_DIR

# Backup database
cd /home/gameplan/GamePlan
./scripts/backup.sh

# Backup configuration
tar -czf $BACKUP_DIR/gameplan_config_$DATE.tar.gz .env docker-compose.yml

# Keep only last 7 days of backups
find $BACKUP_DIR -name "*.tar.gz" -mtime +7 -delete
find $BACKUP_DIR -name "*.archive" -mtime +7 -delete

echo "$(date): Backup completed"
```

```bash
# Make executable
chmod +x ~/backup-gameplan.sh

# Add to crontab (daily backup at 2 AM)
echo "0 2 * * * /home/gameplan/backup-gameplan.sh >> /home/gameplan/backup.log 2>&1" | crontab -
```

---

## 🚨 Troubleshooting

### Common Issues and Solutions

#### Docker Permission Denied
```bash
# If you get permission denied errors
sudo usermod -aG docker $USER
newgrp docker
# Or logout and login again
```

#### Port Already in Use
```bash
# Check what's using port 3000
sudo netstat -tulpn | grep :3000
sudo lsof -i :3000

# Kill process using port
sudo kill -9 <PID>
```

#### Database Connection Issues
```bash
# Check MongoDB container
docker-compose logs mongodb

# Restart database
docker-compose restart mongodb

# Check database health
docker-compose exec mongodb mongosh --eval "db.adminCommand('ping')"
```

#### SSL Certificate Issues
```bash
# Check certificate status
sudo certbot certificates

# Renew certificate manually
sudo certbot renew

# Test Nginx configuration
sudo nginx -t
```

#### Application Won't Start
```bash
# Check all container status
docker-compose ps

# View detailed logs
docker-compose logs --tail=100

# Restart all services
docker-compose down && docker-compose up -d
```

#### High Memory Usage
```bash
# Check system resources
htop
free -h
df -h

# Check Docker resource usage
docker stats

# Restart containers to free memory
docker-compose restart
```

### Log Locations
- **Application logs**: `docker-compose logs gameplan-app`
- **Database logs**: `docker-compose logs mongodb`
- **Nginx logs**: `/var/log/nginx/`
- **System logs**: `sudo journalctl -u gameplan.service`
- **Health logs**: `/home/gameplan/health.log`
- **Backup logs**: `/home/gameplan/backup.log`

---

## 🔧 Performance Optimization

### System Optimization
```bash
# Increase file watchers (for development)
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf

# Optimize network settings
echo 'net.core.somaxconn = 65535' | sudo tee -a /etc/sysctl.conf
echo 'net.ipv4.tcp_max_syn_backlog = 65535' | sudo tee -a /etc/sysctl.conf

# Apply changes
sudo sysctl -p
```

### Docker Optimization
```bash
# Clean up unused Docker resources
docker system prune -f

# Set up log rotation for Docker
sudo nano /etc/docker/daemon.json
```

Add this content:
```json
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "10m",
    "max-file": "3"
  }
}
```

```bash
# Restart Docker
sudo systemctl restart docker
```

---

## 📋 Security Checklist

### Pre-Production Security Audit
- [ ] Changed all default passwords in `.env`
- [ ] Configured UFW firewall with minimal required ports
- [ ] Disabled SSH root login
- [ ] Enabled SSH key-based authentication
- [ ] Configured SSL/TLS certificates
- [ ] Set up automatic security updates
- [ ] Configured log monitoring
- [ ] Set up automated backups
- [ ] Tested disaster recovery procedures
- [ ] Reviewed application logs for errors
- [ ] Verified health check endpoints
- [ ] Configured rate limiting
- [ ] Set up monitoring alerts

### Automatic Security Updates
```bash
# Install unattended upgrades
sudo apt install -y unattended-upgrades

# Configure automatic updates
sudo dpkg-reconfigure -plow unattended-upgrades

# Check configuration
sudo nano /etc/apt/apt.conf.d/50unattended-upgrades
```

---

## 🎯 Quick Commands Reference

### Daily Operations
```bash
# Check application status
docker-compose ps
curl http://localhost:3000/api/health

# View logs
docker-compose logs -f gameplan-app

# Restart application
docker-compose restart gameplan-app

# Update application
git pull
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

### Maintenance Commands
```bash
# Backup database
cd /home/gameplan/GamePlan && ./scripts/backup.sh

# Clean Docker resources
docker system prune -f

# Check disk usage
df -h
docker system df

# Monitor resources
htop
docker stats
```

### Emergency Commands
```bash
# Stop all services
docker-compose down

# Emergency restart
sudo systemctl restart gameplan.service

# Check system health
sudo systemctl status gameplan.service
curl http://localhost:3000/api/health

# View recent logs
docker-compose logs --tail=50 gameplan-app
```

---

## 📞 Support and Resources

### Documentation Links
- [Main Deployment Guide](DEPLOYMENT.md) - Comprehensive Docker deployment
- [GitHub Repository](https://github.com/cafarnfield/GamePlan)
- [Docker Documentation](https://docs.docker.com/)
- [Ubuntu Server Guide](https://ubuntu.com/server/docs)

### Health Check URLs
- **Application Health**: `http://your-domain.com/api/health`
- **Database Health**: `http://your-domain.com/api/health/database`
- **System Health**: `http://your-domain.com/api/health/system`

### Getting Help
1. Check the logs: `docker-compose logs`
2. Review this documentation
3. Check the GitHub repository issues
4. Verify system resources: `htop`, `df -h`
5. Test network connectivity: `curl http://localhost:3000/api/health`

---

## 🎉 Deployment Complete!

Your GamePlan application is now successfully deployed on Ubuntu with:

✅ **Docker containerization** for easy management  
✅ **Automatic startup** on system boot  
✅ **SSL encryption** for secure connections  
✅ **Reverse proxy** for production traffic  
✅ **Automated backups** for data protection  
✅ **Health monitoring** for system reliability  
✅ **Security hardening** for production use  

**Access your application at**: `https://your-domain.com`  
**Admin interface**: Login with your configured admin credentials  
**Database admin**: `https://your-domain.com:8081` (if enabled)  

**Next Steps:**
1. Configure your domain DNS to point to your server
2. Test all functionality thoroughly
3. Set up monitoring alerts
4. Review security settings
5. Plan regular maintenance schedule

**Congratulations! Your GamePlan application is production-ready! 🚀**
