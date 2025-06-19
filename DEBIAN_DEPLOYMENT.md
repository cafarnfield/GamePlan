# GamePlan Debian Deployment Guide

**Complete deployment guide for Debian 11/12 (Bullseye/Bookworm)**

## 🚀 Quick Deployment

### **One-Command Installation:**
```bash
# Download and run the installation script
curl -fsSL https://raw.githubusercontent.com/cafarnfield/GamePlan/main/scripts/debian-install.sh | bash
```

### **Manual Installation:**
```bash
git clone https://github.com/cafarnfield/GamePlan.git
cd GamePlan
chmod +x scripts/debian-install.sh
./scripts/debian-install.sh
```

---

## 📋 System Requirements

- **OS**: Debian 11 (Bullseye) or Debian 12 (Bookworm)
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 20GB minimum, 40GB recommended
- **Network**: Internet connection required
- **Access**: sudo privileges required

---

## 🔧 Manual Step-by-Step Installation

### **1. Update System**
```bash
sudo apt update && sudo apt upgrade -y
sudo apt install -y curl wget git unzip software-properties-common apt-transport-https ca-certificates gnupg lsb-release
```

### **2. Install Docker**
```bash
# Remove old Docker versions
sudo apt remove -y docker docker-engine docker.io containerd runc 2>/dev/null || true

# Add Docker's official GPG key
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/debian/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg

# Add Docker repository
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/debian \
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
```

### **3. Logout and Login**
```bash
# IMPORTANT: Logout and login again to apply docker group membership
# Or run: newgrp docker
```

### **4. Clone GamePlan**
```bash
git clone https://github.com/cafarnfield/GamePlan.git
cd GamePlan
```

### **5. Configure Environment**
```bash
cp .env.example .env
nano .env  # Edit with your settings
```

### **6. Deploy Application**
```bash
docker compose up -d
```

### **7. Initialize Admin User**
```bash
docker compose --profile init up init-admin
```

---

## 🚨 Common Issues & Solutions

### **Issue 1: Docker Permission Denied**
```
permission denied while trying to connect to the Docker daemon socket
```

**Solution:**
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Logout and login again, or run:
newgrp docker

# Verify docker works without sudo
docker ps
```

### **Issue 2: STEAM_API_KEY Warning**
```
WARN [0000] The "STEAM_API_KEY" variable is not set
```

**Solution (Optional):**
```bash
# Edit .env file
nano .env

# Add Steam API key (optional - app works without it)
STEAM_API_KEY=your_steam_api_key_here

# Restart services
docker compose restart
```

### **Issue 3: Docker Compose Version Warnings**
```
the attribute `version` is obsolete
```

**Solution:**
These are just warnings about newer Docker Compose format. No action needed - functionality isn't affected.

### **Issue 4: Container Build Failures**
```bash
# Clean up and rebuild
docker compose down
docker system prune -f
docker compose build --no-cache
docker compose up -d
```

### **Issue 5: Port Already in Use**
```bash
# Check what's using the port
sudo netstat -tulpn | grep :3000

# Stop conflicting service or change port in .env
```

---

## 🔐 Security Configuration

### **Configure UFW Firewall**
```bash
# Install and configure UFW
sudo apt install -y ufw

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Allow SSH
sudo ufw allow 22/tcp

# Allow GamePlan
sudo ufw allow 3000/tcp

# Allow HTTP/HTTPS (for reverse proxy)
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

# Enable firewall
sudo ufw --force enable

# Check status
sudo ufw status
```

### **Generate Secure Passwords**
```bash
# Generate secure passwords for .env
openssl rand -base64 32  # For SESSION_SECRET
openssl rand -base64 16  # For ADMIN_PASSWORD
openssl rand -base64 32  # For MONGO_ROOT_PASSWORD
openssl rand -base64 32  # For MONGO_PASSWORD
```

---

## 🌐 Nginx Reverse Proxy Setup

### **Install Nginx**
```bash
sudo apt install -y nginx
```

### **Configure Nginx**
```bash
# Copy GamePlan Nginx configuration
sudo cp configs/nginx-gameplan.conf /etc/nginx/sites-available/gameplan

# Edit domain name
sudo nano /etc/nginx/sites-available/gameplan
# Replace 'your-domain.com' with your actual domain

# Enable site
sudo ln -sf /etc/nginx/sites-available/gameplan /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test configuration
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

---

## 🔒 SSL/TLS Setup with Let's Encrypt

### **Install Certbot**
```bash
sudo apt install -y certbot python3-certbot-nginx
```

### **Obtain SSL Certificate**
```bash
# Replace with your domain
sudo certbot --nginx -d your-domain.com -d www.your-domain.com
```

### **Auto-renewal**
```bash
# Test renewal
sudo certbot renew --dry-run

# Add cron job
echo "0 12 * * * /usr/bin/certbot renew --quiet" | sudo crontab -
```

---

## 🔄 Systemd Service Setup

### **Create Service File**
```bash
sudo cp configs/gameplan.service /etc/systemd/system/
sudo nano /etc/systemd/system/gameplan.service
# Update WorkingDirectory and User paths

# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable gameplan.service
sudo systemctl start gameplan.service

# Check status
sudo systemctl status gameplan.service
```

---

## 📊 Monitoring & Maintenance

### **Check Application Status**
```bash
# Check containers
docker compose ps

# Check logs
docker compose logs -f gameplan-app

# Check health
curl http://localhost:3000/api/health

# Check system service
sudo systemctl status gameplan
```

### **Update Application**
```bash
cd GamePlan
git pull
docker compose down
docker compose up -d
```

### **Backup Database**
```bash
# Create backup
docker compose exec gameplan-mongodb mongodump --out /backup

# Or use backup script
./scripts/backup.sh
```

---

## 🎯 Access Information

After successful deployment:

- **Application**: `http://your-server-ip:3000`
- **With domain**: `https://your-domain.com`
- **Database Admin**: `http://your-server-ip:8081`
- **Health Check**: `http://your-server-ip:3000/api/health`

### **Default Admin Credentials**
Check your `.env` file for:
- Email: Value of `ADMIN_EMAIL`
- Password: Value of `ADMIN_PASSWORD`

---

## 🔧 Useful Commands

```bash
# Application Management
docker compose ps                    # Check status
docker compose logs -f gameplan-app  # View logs
docker compose restart              # Restart all services
docker compose down                 # Stop all services
docker compose up -d                # Start all services

# System Service Management
sudo systemctl status gameplan      # Check service status
sudo systemctl restart gameplan     # Restart service
sudo systemctl stop gameplan        # Stop service
sudo systemctl start gameplan       # Start service

# Maintenance
docker system prune -f              # Clean up unused containers
docker compose pull                 # Update images
git pull && docker compose restart  # Update application

# Monitoring
htop                                # System resources
docker stats                       # Container resources
sudo journalctl -u gameplan -f     # Service logs
```

---

## 🚨 Troubleshooting

### **Application Won't Start**
```bash
# Check logs
docker compose logs gameplan-app

# Check environment
cat .env

# Rebuild containers
docker compose down
docker compose build --no-cache
docker compose up -d
```

### **Database Connection Issues**
```bash
# Check MongoDB logs
docker compose logs gameplan-mongodb

# Check network
docker network ls
docker network inspect gameplan_gameplan-network
```

### **Permission Issues**
```bash
# Fix file permissions
sudo chown -R $USER:$USER .
chmod +x scripts/*.sh

# Fix docker permissions
sudo usermod -aG docker $USER
newgrp docker
```

### **Port Conflicts**
```bash
# Check port usage
sudo netstat -tulpn | grep :3000
sudo lsof -i :3000

# Change port in .env if needed
```

---

## 📚 Additional Resources

- **Docker Documentation**: [docs.docker.com](https://docs.docker.com)
- **Nginx Documentation**: [nginx.org/en/docs](https://nginx.org/en/docs)
- **Let's Encrypt**: [letsencrypt.org](https://letsencrypt.org)
- **Debian Documentation**: [debian.org/doc](https://www.debian.org/doc)

---

## 🎉 Success!

Your GamePlan application should now be running successfully on Debian! 

For additional help or issues, check the main [DEPLOYMENT.md](DEPLOYMENT.md) guide or create an issue on GitHub.
