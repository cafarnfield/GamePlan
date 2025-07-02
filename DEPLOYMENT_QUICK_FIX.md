# 🚀 Quick Fix: Stop App from Dying During Git Sync

## ❌ The Problem
Your `deploy-update.sh` script kills your app because it uses `git reset --hard` which overwrites production files.

## ✅ The Solution
Use the new **safe deployment script** instead:

### **On Your Server:**
```bash
# Navigate to GamePlan directory
cd /home/chrisadmin/GamePlan

# Make script executable
chmod +x safe-deploy-update.sh

# Run safe deployment
./safe-deploy-update.sh
```

### **On Windows (Development):**
```cmd
# Double-click or run:
safe-deploy-update.bat
```

## 🔧 What Changed

| **Old Script** | **New Script** |
|----------------|----------------|
| `git reset --hard` (destroys files) | `git merge` (preserves files) |
| Always restarts everything | Only restarts when needed |
| No backup/rollback | Automatic backup & rollback |
| Overwrites production config | Protects production config |
| Basic health check | Comprehensive health verification |

## 🛡️ Protected Files
These files are now safe from git sync overwrites:
- `.env` and `.env.production`
- `docker-compose.production.yml`
- `logs/` directory
- `deployment-backups/` directory

## 🎯 Key Benefits
- ✅ **App stays running** during most updates
- ✅ **Automatic rollback** if anything fails
- ✅ **Production config preserved**
- ✅ **Smart restart logic** (only when needed)
- ✅ **Comprehensive health checks**

## 🆘 Emergency Fallback
If the new script fails, use the old one:
```bash
./deploy-update.sh
```

---
**Result: No more app crashes during repository sync!** 🎉
