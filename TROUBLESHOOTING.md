# GamePlan Troubleshooting Guide

**Common issues and solutions for GamePlan deployment**

## 🚨 Docker Permission Issues

### **Problem: Permission denied while trying to connect to Docker daemon**
```
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock
```

**Solution:**
```bash
# Add user to docker group
sudo usermod -aG docker $USER

# Apply changes immediately
newgrp docker

# Or logout and login again
exit
# Then login again

# Verify it works
docker ps
```

---

## ⚠️ Environment Variable Warnings

### **Problem: STEAM_API_KEY variable not set**
```
WARN [0000] The "STEAM_API_KEY" variable is not set. Defaulting to a blank string.
```

**Solution (Optional):**
This is just a warning - Steam integration works without an API key. To remove the warning:

```bash
# Edit .env file
nano .env

# Add Steam API key (get from https://steamcommunity.com/dev/apikey)
STEAM_API_KEY=your_steam_api_key_here

# Restart services
docker compose restart
```

**Note:** The application works perfectly without a Steam API key.

---

## 📝 Docker Compose Version Warnings

### **Problem: Docker Compose version warnings**
```
WARN [0000] the attribute `version` is obsolete, it will be ignored
```

**Solution:**
These are harmless warnings about newer Docker Compose format. No action needed - functionality isn't affected.

---

## 🔧 Container Issues

### **Problem: Container fails to start**
```
dependency failed to start: container gameplan-app is unhealthy
```

**Solutions:**
```bash
# Check container logs
docker compose logs gameplan-app

# Check all container status
docker compose ps

# Restart specific container
docker compose restart gameplan-app

# Full restart
docker compose down
docker compose up -d

# Clean rebuild
docker compose down
docker system prune -f
docker compose build --no-cache
docker compose up -d
```

---

## 🌐 Network and Port Issues

### **Problem: Port already in use**
```
Error starting userland proxy: listen tcp4 0.0.0.0:3000: bind: address already in use
```

**Solutions:**
```bash
# Check what's using the port
sudo netstat -tulpn | grep :3000
sudo lsof -i :3000

# Kill the process using the port
sudo kill -9 <PID>

# Or change port in .env file
nano .env
# Change PORT=3000 to PORT=3001

# Restart services
docker compose down
docker compose up -d
```

---

## 🗄️ Database Connection Issues

### **Problem: MongoDB connection failed**
```
MongoNetworkError: failed to connect to server
```

**Solutions:**
```bash
# Check MongoDB container
docker compose logs gameplan-mongodb

# Check if MongoDB is running
docker compose ps | grep mongodb

# Restart MongoDB
docker compose restart gameplan-mongodb

# Check network connectivity
docker network ls
docker network inspect gameplan_gameplan-network

# Full database reset (WARNING: loses data)
docker compose down
docker volume rm gameplan_mongodb_data
docker compose up -d
```

---

## 🔐 Authentication Issues

### **Problem: Admin user not created**
```
Admin initialization failed
```

**Solutions:**
```bash
# Run admin initialization manually
docker compose --profile init up init-admin

# Check admin initialization logs
docker compose logs init-admin

# Verify admin user exists
docker compose exec gameplan-mongodb mongosh gameplan --eval "db.users.find({role: 'admin'})"

# Create admin manually if needed
docker compose exec gameplan-app node createAdmin.js
```

---

## 🌍 Access Issues

### **Problem: Can't access application from browser**

**Check firewall:**
```bash
# Check UFW status
sudo ufw status

# Allow port 3000
sudo ufw allow 3000/tcp

# Check if application is running
curl http://localhost:3000/api/health
```

**Check application status:**
```bash
# Check if containers are running
docker compose ps

# Check application logs
docker compose logs -f gameplan-app

# Test local access
curl http://localhost:3000
```

---

## 🔄 Update Issues

### **Problem: Application won't update**

**Solutions:**
```bash
# Pull latest changes
git pull

# Force rebuild
docker compose down
docker compose build --no-cache
docker compose up -d

# Clean Docker cache
docker system prune -a -f

# Reset to clean state
docker compose down
docker volume prune -f
git pull
docker compose up -d
```

---

## 📊 Performance Issues

### **Problem: Application running slowly**

**Check resources:**
```bash
# Check system resources
htop

# Check Docker container resources
docker stats

# Check disk space
df -h

# Check memory usage
free -h
```

**Optimize:**
```bash
# Clean up Docker
docker system prune -f

# Restart services
docker compose restart

# Check for memory leaks in logs
docker compose logs gameplan-app | grep -i memory
```

---

## 🔍 Debugging Commands

### **General Debugging:**
```bash
# Check all container status
docker compose ps

# View all logs
docker compose logs

# View specific service logs
docker compose logs -f gameplan-app
docker compose logs -f gameplan-mongodb

# Check health endpoint
curl http://localhost:3000/api/health

# Check environment variables
docker compose exec gameplan-app env | grep -E "(MONGO|PORT|NODE_ENV)"

# Access container shell
docker compose exec gameplan-app bash
docker compose exec gameplan-mongodb bash

# Check network connectivity
docker compose exec gameplan-app ping gameplan-mongodb
```

### **Database Debugging:**
```bash
# Access MongoDB shell
docker compose exec gameplan-mongodb mongosh gameplan

# Check database collections
docker compose exec gameplan-mongodb mongosh gameplan --eval "show collections"

# Check user count
docker compose exec gameplan-mongodb mongosh gameplan --eval "db.users.countDocuments()"

# Check admin users
docker compose exec gameplan-mongodb mongosh gameplan --eval "db.users.find({role: 'admin'})"
```

---

## 🆘 Emergency Recovery

### **Complete Reset (WARNING: Loses all data):**
```bash
# Stop everything
docker compose down

# Remove all volumes (loses database data)
docker volume prune -f

# Remove all containers and images
docker system prune -a -f

# Fresh start
git pull
docker compose up -d
docker compose --profile init up init-admin
```

### **Backup Before Reset:**
```bash
# Backup database
docker compose exec gameplan-mongodb mongodump --out /backup

# Copy backup out of container
docker compose cp gameplan-mongodb:/backup ./mongodb-backup

# After reset, restore if needed
docker compose cp ./mongodb-backup gameplan-mongodb:/backup
docker compose exec gameplan-mongodb mongorestore /backup
```

---

## 📞 Getting Help

### **Collect Debug Information:**
```bash
# System information
uname -a
docker --version
docker compose version

# Container status
docker compose ps

# Recent logs
docker compose logs --tail=50

# Health check
curl -v http://localhost:3000/api/health

# Environment check
cat .env | grep -v PASSWORD | grep -v SECRET
```

### **Where to Get Help:**
- **GitHub Issues**: [GamePlan Issues](https://github.com/cafarnfield/GamePlan/issues)
- **Documentation**: [DEPLOYMENT.md](DEPLOYMENT.md), [UBUNTU_DEPLOYMENT.md](UBUNTU_DEPLOYMENT.md), [DEBIAN_DEPLOYMENT.md](DEBIAN_DEPLOYMENT.md)
- **Docker Documentation**: [docs.docker.com](https://docs.docker.com)

---

## ✅ Success Indicators

**Your deployment is working correctly when:**
- ✅ `docker compose ps` shows all containers as "Up"
- ✅ `curl http://localhost:3000/api/health` returns `{"status":"healthy"}`
- ✅ You can access the application in your browser
- ✅ You can login with admin credentials
- ✅ No error messages in `docker compose logs`

**Your deployment is ready for production when:**
- ✅ SSL certificate is configured
- ✅ Firewall is properly configured
- ✅ Backup system is in place
- ✅ Monitoring is set up
- ✅ Domain name is configured
