# GamePlan Production Deployment Guide

## Overview
This guide ensures smooth production deployments by addressing common configuration issues and providing bulletproof deployment procedures.

## Problems Resolved in This Repository

### 1. Development Override File Conflict ✅ FIXED
**Issue**: `docker-compose.override.yml` was forcing development settings in production
- **Root Cause**: Docker Compose automatically loads override files, causing conflicts
- **Solution**: Renamed to `docker-compose.development.yml` (development-only)
- **Prevention**: Deployment scripts now automatically disable any override files

### 2. Missing MongoDB Environment Variables ✅ FIXED
**Issue**: MongoDB authentication failures due to missing `MONGO_PASSWORD`
- **Root Cause**: Environment variable not passed to MongoDB container
- **Solution**: Added `MONGO_PASSWORD=${MONGO_PASSWORD}` to `docker-compose.production.yml.example`
- **Prevention**: Template now includes all required environment variables

### 3. Incorrect Docker Compose Commands ✅ FIXED
**Issue**: Scripts using wrong compose files for production
- **Root Cause**: Using `docker compose up` instead of production-specific files
- **Solution**: All scripts now use `-f docker-compose.yml -f docker-compose.production.yml`
- **Prevention**: Automated production file creation and validation

### 4. Admin User Creation ✅ FIXED
**Issue**: Admin credentials not working after deployment
- **Root Cause**: Admin user never created in database
- **Solution**: Deployment scripts now run `scripts/init-admin.js` automatically
- **Prevention**: Automated admin user creation in deployment process

## Deployment Methods

### Method 1: Fresh Installation (Recommended for new servers)
```bash
# On the server
cd ~/GamePlan
chmod +x gameplan-deploy-fixed.sh
./gameplan-deploy-fixed.sh
```

### Method 2: Safe Update (For existing installations)
```bash
# On the server
cd ~/GamePlan
chmod +x deploy-update-enhanced.sh
./deploy-update-enhanced.sh
```

## File Structure for Production

### Required Files (Auto-created by scripts):
- `.env.production` - Production environment variables
- `docker-compose.production.yml` - Production Docker configuration

### Template Files (Tracked in Git):
- `docker-compose.production.yml.example` - Production template
- `.env.local.example` - Local development template

### Development Files (Not used in production):
- `docker-compose.development.yml` - Development overrides
- `docker-compose.local.yml` - Local development setup

## Environment Variable Requirements

### Critical Production Variables:
```bash
NODE_ENV=production
MONGO_ROOT_PASSWORD=<secure-password>
MONGO_PASSWORD=<secure-password>
SESSION_SECRET=<secure-secret>
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=<secure-password>
```

## Deployment Script Features

### gameplan-deploy-fixed.sh (Fresh Installation):
- ✅ Automatic production file creation
- ✅ Development override disabling
- ✅ Secure password generation
- ✅ Admin user creation
- ✅ Firewall configuration
- ✅ Systemd service setup

### deploy-update-enhanced.sh (Safe Updates):
- ✅ Pre-flight validation
- ✅ Configuration backup
- ✅ Automatic healing
- ✅ Production file validation
- ✅ Health verification
- ✅ Automatic rollback on failure

## Manual Deployment Steps (If scripts fail)

### 1. Prepare Environment:
```bash
cd ~/GamePlan
cp docker-compose.production.yml.example docker-compose.production.yml
cp .env.example .env.production
```

### 2. Configure Environment:
```bash
# Edit .env.production with your settings
nano .env.production
```

### 3. Disable Development Overrides:
```bash
# If docker-compose.override.yml exists
mv docker-compose.override.yml docker-compose.override.yml.disabled
```

### 4. Deploy:
```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml down
docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

### 5. Create Admin User:
```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml exec gameplan-app node scripts/init-admin.js
```

## Troubleshooting

### Issue: "503 Service Unavailable"
**Cause**: Development override file active
**Solution**: 
```bash
mv docker-compose.override.yml docker-compose.override.yml.disabled
docker compose -f docker-compose.yml -f docker-compose.production.yml restart
```

### Issue: "Authentication failed" (MongoDB)
**Cause**: Missing MONGO_PASSWORD environment variable
**Solution**: 
```bash
# Add to docker-compose.production.yml under mongodb.environment:
- MONGO_PASSWORD=${MONGO_PASSWORD}
```

### Issue: Admin login not working
**Cause**: Admin user not created
**Solution**: 
```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml exec gameplan-app node scripts/init-admin.js
```

### Issue: Wrong environment mode
**Cause**: NODE_ENV not set correctly
**Solution**: 
```bash
# In .env.production:
NODE_ENV=production
```

## Development vs Production

### Development Mode:
- Uses `docker-compose.development.yml` (if needed)
- NODE_ENV=development
- Auto-login features enabled
- Detailed error messages
- Hot reloading

### Production Mode:
- Uses `docker-compose.production.yml`
- NODE_ENV=production
- Security features enabled
- Error logging only
- Optimized performance

## Security Considerations

### Protected Files (Not in Git):
- `.env.production` - Contains sensitive passwords
- `docker-compose.production.yml` - Server-specific configuration
- `config-backups/` - Configuration backups

### Tracked Files (Safe for Git):
- `docker-compose.production.yml.example` - Template only
- `.env.local.example` - Template only
- All deployment scripts

## Backup and Recovery

### Automatic Backups:
- Configuration files backed up before updates
- Stored in `config-backups/` directory
- Includes manifest with git status

### Manual Backup:
```bash
tar -czf backup-$(date +%Y%m%d).tar.gz .env.production docker-compose.production.yml
```

### Recovery:
```bash
tar -xzf backup-YYYYMMDD.tar.gz
docker compose -f docker-compose.yml -f docker-compose.production.yml restart
```

## Health Monitoring

### Health Check Endpoints:
- `http://your-server:3000/api/health` - Basic health
- `http://your-server:3000/api/version` - Version info

### Service Status:
```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml ps
```

### Logs:
```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml logs -f
```

## Future Updates

When updating from GitHub:
1. Use `deploy-update-enhanced.sh` for safe updates
2. Script automatically handles configuration healing
3. Automatic rollback if deployment fails
4. All production configurations preserved

## Summary

This repository now includes all fixes for the deployment issues encountered:
- ✅ Production configuration template with MONGO_PASSWORD fix
- ✅ Deployment scripts using correct compose files
- ✅ Automatic development override disabling
- ✅ Admin user creation automation
- ✅ Configuration validation and healing
- ✅ Comprehensive error handling and rollback

Future deployments from this repository should be smooth and error-free!
