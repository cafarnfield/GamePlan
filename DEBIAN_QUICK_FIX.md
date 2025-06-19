# GamePlan Debian Quick Fix Guide

**Immediate solutions for your current deployment issues**

Based on your screenshot, your GamePlan deployment is **working correctly** but has some minor issues to address.

## ✅ What's Working
- ✅ Docker containers are running
- ✅ Application is building successfully
- ✅ Database is connected
- ✅ Admin user initialization completed
- ✅ GamePlan is accessible

## 🔧 Quick Fixes Needed

### **1. Fix Log Directory Permissions (Critical)**
```bash
# Rebuild containers with fixed permissions
docker compose down
docker compose build --no-cache
docker compose up -d
```

**Why this matters:** The application can't create log directories due to Docker container permissions.

### **2. Fix Docker User Permissions (Important)**
```bash
# Add your user to docker group
sudo usermod -aG docker $USER

# Apply changes immediately
newgrp docker

# Test it works
docker ps
```

**Why this matters:** You're currently using `sudo` for Docker commands, which can cause permission issues.

### **2. Optional: Remove STEAM_API_KEY Warning**
```bash
# Edit environment file
nano .env

# Add this line (optional - app works without it):
STEAM_API_KEY=your_steam_api_key_here

# Restart to apply changes
docker compose restart
```

**Note:** This warning is harmless - Steam integration works without an API key.

### **3. Ignore Docker Compose Version Warnings**
The warnings about `version` being obsolete are harmless. Your Docker Compose is newer and these warnings don't affect functionality.

## 🎯 Verify Everything Works

### **Check Application Status:**
```bash
# Check containers
docker compose ps

# Test health endpoint
curl http://localhost:3000/api/health

# View logs
docker compose logs -f gameplan-app
```

### **Access Your Application:**
- **Local**: `http://localhost:3000`
- **External**: `http://your-server-ip:3000`
- **Health Check**: `http://your-server-ip:3000/api/health`

### **Admin Login:**
Check your credentials file:
```bash
cat ~/gameplan-credentials.txt
```

## 🚀 Next Steps (Optional)

### **1. Set Up Domain & SSL (Recommended for Production)**
```bash
# Install Nginx
sudo apt install -y nginx

# Copy configuration
sudo cp configs/nginx-gameplan.conf /etc/nginx/sites-available/gameplan

# Edit domain name
sudo nano /etc/nginx/sites-available/gameplan
# Replace 'your-domain.com' with your actual domain

# Enable site
sudo ln -sf /etc/nginx/sites-available/gameplan /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test and restart
sudo nginx -t
sudo systemctl restart nginx

# Set up SSL
sudo apt install -y certbot python3-certbot-nginx
sudo certbot --nginx -d your-domain.com
```

### **2. Secure Firewall (If Not Done)**
```bash
# Check current firewall status
sudo ufw status

# If not configured, set up basic rules
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow 22/tcp
sudo ufw allow 3000/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw --force enable
```

### **3. Set Up Auto-Start Service**
```bash
# Create systemd service
sudo cp configs/gameplan.service /etc/systemd/system/

# Edit paths if needed
sudo nano /etc/systemd/system/gameplan.service

# Enable service
sudo systemctl daemon-reload
sudo systemctl enable gameplan.service
sudo systemctl start gameplan.service

# Check status
sudo systemctl status gameplan.service
```

## 📊 Monitoring Commands

```bash
# Check application status
docker compose ps
curl http://localhost:3000/api/health

# View logs
docker compose logs -f gameplan-app

# Check system resources
htop
docker stats

# Restart if needed
docker compose restart

# Update application
git pull && docker compose down && docker compose up -d
```

## 🆘 If Something Goes Wrong

### **Application Won't Start:**
```bash
docker compose down
docker compose up -d
docker compose logs gameplan-app
```

### **Database Issues:**
```bash
docker compose logs gameplan-mongodb
docker compose restart gameplan-mongodb
```

### **Permission Issues:**
```bash
sudo usermod -aG docker $USER
newgrp docker
```

### **Complete Reset (Last Resort):**
```bash
docker compose down
docker system prune -f
docker compose up -d
```

## 🎉 Success!

Your GamePlan deployment is working! The warnings you see are normal and don't affect functionality. After fixing the Docker permissions, you'll have a fully functional GamePlan installation.

**Key Points:**
- ✅ Your deployment is successful
- ⚠️ Docker permission warning is normal until you logout/login
- ⚠️ STEAM_API_KEY warning is optional to fix
- ⚠️ Docker Compose version warnings are harmless
- 🚀 Application is ready to use

**Access your GamePlan application at:** `http://your-server-ip:3000`

For complete documentation, see:
- [DEBIAN_DEPLOYMENT.md](DEBIAN_DEPLOYMENT.md) - Full Debian guide
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md) - Detailed troubleshooting
- [DEPLOYMENT.md](DEPLOYMENT.md) - General Docker deployment
