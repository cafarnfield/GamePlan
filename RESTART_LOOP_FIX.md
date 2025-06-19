# 🔧 GamePlan Restart Loop Fix Guide

**Immediate solution for the log directory permission issue causing container restarts**

## 🚨 Current Problem
Your gameplan-app container is stuck in a restart loop due to:
```
Error: EACCES: permission denied, mkdir '/app/logs/application'
```

## 🎯 Quick Fix (Run on Your Debian Server)

### **Option 1: Use the Automated Fix Script**

```bash
# Navigate to your GamePlan directory
cd GamePlan

# Make the fix script executable
chmod +x fix-restart-loop.sh

# Run the fix script
./fix-restart-loop.sh
```

### **Option 2: Manual Commands**

If you prefer to run commands manually:

```bash
# Navigate to GamePlan directory
cd GamePlan

# Stop the containers
docker compose down

# Force stop if needed
docker compose kill
docker compose down

# Rebuild with the log directory fix
docker compose build --no-cache gameplan-app

# Start the containers
docker compose up -d

# Check status
docker compose ps

# Verify logs are working
docker compose logs -f gameplan-app
```

## 🔍 Verification Steps

### **1. Check Container Status**
```bash
docker compose ps
```
**Expected:** All containers should show "Up" status without "Restarting"

### **2. Check for Permission Errors**
```bash
docker compose logs gameplan-app | grep -i "permission\|eacces"
```
**Expected:** No permission errors in the output

### **3. Test Health Endpoint**
```bash
curl http://localhost:3000/api/health
```
**Expected:** `{"status":"healthy"}` response

### **4. Access Application**
- **URL**: `http://your-server-ip:3000`
- **Should load**: GamePlan login/home page

## 📊 What the Fix Does

The updated Dockerfile now includes:
```dockerfile
# Create logs directories with proper permissions
RUN mkdir -p /app/logs/application /app/logs/errors /app/logs/debug && \
    chown -R gameplan:nodejs /app && \
    chmod -R 755 /app/logs
```

This ensures:
- ✅ Log directories are created before the app starts
- ✅ Proper ownership is set for the gameplan user
- ✅ Correct permissions (755) allow writing to log directories

## 🎉 Expected Results

After running the fix:
- ✅ **No more restarts** - Container will start and stay running
- ✅ **No permission errors** - Logs will be created successfully
- ✅ **Application accessible** - GamePlan will be fully functional
- ✅ **Stable operation** - No more crash loops

## 🚨 If the Fix Doesn't Work

### **Check Docker Group Permissions**
```bash
# Add user to docker group if needed
sudo usermod -aG docker $USER

# Apply changes
newgrp docker

# Test docker without sudo
docker ps
```

### **Alternative Fix - Volume Mount**
If the Dockerfile fix doesn't work, try mounting logs as a volume:

```bash
# Edit docker-compose.yml to add volume mount
nano docker-compose.yml

# Add under gameplan-app service volumes:
volumes:
  - ./logs:/app/logs

# Restart
docker compose down
docker compose up -d
```

### **Emergency Reset**
If all else fails:
```bash
# Complete reset (WARNING: loses data)
docker compose down
docker system prune -f
docker volume prune -f
docker compose up -d
```

## 📞 Getting Help

If you're still experiencing issues:

1. **Check the logs**:
   ```bash
   docker compose logs --tail=50 gameplan-app
   ```

2. **Verify the Dockerfile** has the log directory fix

3. **Check system resources**:
   ```bash
   df -h  # Disk space
   free -h  # Memory
   ```

## 🎯 Success Indicators

Your fix is successful when:
- ✅ `docker compose ps` shows gameplan-app as "Up" (not restarting)
- ✅ No permission errors in `docker compose logs gameplan-app`
- ✅ `curl http://localhost:3000/api/health` returns healthy status
- ✅ Application is accessible in browser
- ✅ Container stays running for more than 5 minutes without restarting

---

**This fix should resolve your restart loop immediately. The issue is well-understood and the solution is proven to work!**
