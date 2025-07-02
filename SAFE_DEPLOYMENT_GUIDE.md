# 🛡️ Safe Deployment Guide for GamePlan

This guide explains how to safely sync your repository to your server without killing your running application.

## 🚨 Problem Solved

**Before:** Your `deploy-update.sh` script used `git reset --hard` which:
- ❌ Overwrote ALL local files including production configurations
- ❌ Removed server-specific files that weren't in git
- ❌ Reset file permissions causing container restart loops
- ❌ Killed your running application during sync

**Now:** The new `safe-deploy-update.sh` script:
- ✅ Backs up production configurations before sync
- ✅ Uses `git merge` instead of destructive `git reset --hard`
- ✅ Preserves local changes and server-specific files
- ✅ Only restarts services when actually needed
- ✅ Automatically rolls back if anything goes wrong
- ✅ Keeps your app running during most updates

## 🚀 How to Use the Safe Deployment Script

### **On Your Server (Debian/Ubuntu):**

1. **Navigate to your GamePlan directory:**
   ```bash
   cd /home/chrisadmin/GamePlan
   ```

2. **Make the script executable:**
   ```bash
   chmod +x safe-deploy-update.sh
   ```

3. **Run the safe deployment:**
   ```bash
   ./safe-deploy-update.sh
   ```

### **What the Script Does:**

1. **🔍 Status Check** - Checks if your app is currently running
2. **💾 Backup** - Creates a backup of all production configurations
3. **📥 Safe Sync** - Uses `git merge` to safely pull changes
4. **✅ Validation** - Validates environment and configuration files
5. **🔄 Smart Restart** - Only restarts if code changes require it
6. **🏥 Health Check** - Verifies the app is working after update
7. **🔙 Auto Rollback** - Automatically rolls back if anything fails

## 📋 Script Output Example

```bash
🚀 GamePlan Safe Deployment Update
===================================

🔧 Checking Application Status
✅ Application is currently running

🔧 Creating Safe Configuration Backup
✅ Configuration backed up to ./deployment-backups/safe_backup_20250102_184500.tar.gz
✅ Backup manifest created

🔧 Safe Git Repository Update
ℹ️  Current commit: abc123def456
ℹ️  Current branch: main
ℹ️  Fetching latest changes from origin...
ℹ️  Repository is 3 commits behind origin/main
ℹ️  Performing safe merge update...
✅ Successfully updated to commit: def456abc789

🔧 Environment Validation
✅ Environment validation passed

🔧 Smart Service Management
ℹ️  Changes detected in src/ - restart required
ℹ️  Performing rolling restart to apply changes...
ℹ️  Building updated images...
ℹ️  Performing rolling restart...
✅ Rolling restart completed

🔧 Health Verification
ℹ️  Verifying application health (max 24 attempts)...
ℹ️  Health check attempt 1/24...
✅ Application is healthy and responding
✅ Health endpoint confirms application is healthy

🔧 Deployment Status
CONTAINER ID   IMAGE                    COMMAND                  CREATED         STATUS                   PORTS                    NAMES
abc123def456   gameplan_gameplan-app    "docker-entrypoint.s…"   2 minutes ago   Up 2 minutes (healthy)   0.0.0.0:3000->3000/tcp   gameplan-app
def456abc789   mongo:7.0                "docker-entrypoint.s…"   2 minutes ago   Up 2 minutes (healthy)   27017/tcp                gameplan-mongodb

✅ 🎉 Safe deployment update completed successfully!

ℹ️  Application URL: http://localhost:3000
ℹ️  Health Check: http://localhost:3000/api/health

ℹ️  Backup created: ./deployment-backups/safe_backup_20250102_184500.tar.gz
ℹ️  To rollback if needed later: tar -xzf ./deployment-backups/safe_backup_20250102_184500.tar.gz && docker compose restart
```

## 🔧 Key Improvements Over Old Script

### **1. No More Destructive Git Operations**
- **Old:** `git reset --hard origin/main` (destroys local changes)
- **New:** `git merge origin/main` (preserves local changes)

### **2. Configuration Protection**
- **Old:** Overwrote production files every time
- **New:** Backs up and preserves production configurations

### **3. Smart Restart Logic**
- **Old:** Always restarted all services
- **New:** Only restarts when code changes actually require it

### **4. Automatic Rollback**
- **Old:** No rollback capability
- **New:** Automatically rolls back if deployment fails

### **5. Health Verification**
- **Old:** Basic health check with short timeout
- **New:** Comprehensive health verification with proper timeout

## 🛡️ Protected Files

The following files are now protected from being overwritten during git sync:

- `.env` (your main environment file)
- `.env.production` (production-specific environment)
- `docker-compose.production.yml` (production docker configuration)
- `docker-compose.override.yml` (development overrides)
- `logs/` directory (application logs)
- `deployment-backups/` directory (backup files)

## 🔄 Rollback Instructions

If you need to rollback to a previous working state:

### **Automatic Rollback (if deployment fails):**
The script automatically rolls back if health checks fail.

### **Manual Rollback:**
```bash
# Find your backup file
ls -la deployment-backups/

# Restore from backup (replace with your backup filename)
tar -xzf deployment-backups/safe_backup_YYYYMMDD_HHMMSS.tar.gz

# Restart services
docker compose restart
```

## 🚨 Emergency Procedures

### **If the Safe Script Fails:**
1. **Check the logs:**
   ```bash
   docker compose logs --tail=50 gameplan-app
   ```

2. **Use the old script as fallback:**
   ```bash
   ./deploy-update.sh
   ```

3. **Manual recovery:**
   ```bash
   # Stop everything
   docker compose down
   
   # Reset to last known good commit
   git reset --hard HEAD~1
   
   # Restart
   docker compose up -d
   ```

## 📊 Monitoring Your Deployment

### **Check Application Status:**
```bash
# Container status
docker compose ps

# Application health
curl http://localhost:3000/api/health

# Recent logs
docker compose logs --tail=20 gameplan-app
```

### **View Backup History:**
```bash
# List all backups
ls -la deployment-backups/

# View backup manifest
cat deployment-backups/backup_manifest_YYYYMMDD_HHMMSS.txt
```

## 🎯 Best Practices

1. **Always use the safe script** for production deployments
2. **Test deployments** in a staging environment first
3. **Monitor logs** after deployment
4. **Keep backups** for at least 30 days
5. **Verify health endpoints** after each deployment

## 🆘 Getting Help

If you encounter issues:

1. **Check the deployment logs** in the script output
2. **Review the backup manifest** for what was changed
3. **Use the rollback procedure** if needed
4. **Check Docker container logs** for application errors

---

**This safe deployment script eliminates the "app killing" issue you were experiencing and provides a robust, production-ready deployment process!**
