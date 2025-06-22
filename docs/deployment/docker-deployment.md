# GamePlan Docker Deployment Guide

## Overview

This comprehensive guide covers deploying GamePlan using Docker Compose with both standard and enhanced deployment systems. The enhanced system provides bulletproof, zero-downtime updates with automatic configuration healing and rollback capabilities.

## Prerequisites

- Docker Engine (20.10.0 or later)
- Docker Compose (2.0.0 or later)
- At least 2GB RAM
- At least 5GB free disk space
- Git (for updates)

## Quick Start

### Standard Deployment

1. **Clone the repository:**
   ```bash
   git clone https://github.com/cafarnfield/GamePlan.git
   cd GamePlan
   ```

2. **Configure environment:**
   ```bash
   cp .env.example .env
   nano .env  # Edit with your settings
   ```

3. **Start the application:**
   ```bash
   docker-compose up -d
   ```

4. **Initialize admin user:**
   ```bash
   docker-compose --profile init up init-admin
   ```

5. **Access the application:**
   - Main application: `http://your-server:3000`
   - Database admin: `http://your-server:8081` (optional)

### Enhanced Deployment (Recommended)

For production environments, use the enhanced deployment system:

```bash
# Run enhanced deployment with validation and healing
./deploy-update-enhanced.sh
```

## Environment Configuration

### Essential Settings

Copy `.env.example` to `.env` and configure the following required variables:

```bash
# Database passwords (generate secure passwords)
MONGO_ROOT_PASSWORD=your_secure_root_password_here
MONGO_PASSWORD=your_secure_app_password_here

# Session security (generate a random 32+ character string)
SESSION_SECRET=your_very_secure_session_secret_key_change_this_in_production

# Initial admin user
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=your_secure_admin_password
ADMIN_NAME=GamePlan Administrator
ADMIN_NICKNAME=Admin

# Environment
NODE_ENV=production
PORT=3000
```

### API Keys (Optional)

```bash
# RAWG API Key (already provided, but you can use your own)
RAWG_API_KEY=3963501b74354e0688413453cb8c6bc4

# Note: Steam integration works automatically without requiring an API key
```

### Database Admin Interface

```bash
# Mongo Express credentials
MONGO_EXPRESS_PASSWORD=your_mongo_express_password
```

## Deployment Systems

### Standard Deployment

Basic Docker Compose deployment suitable for development and simple production setups.

**Commands:**
```bash
# Start all services
docker-compose up -d

# Initialize admin user (run once)
docker-compose --profile init up init-admin

# Enable database admin interface (optional)
docker-compose --profile tools up -d mongo-express
```

### Enhanced Deployment System

Enterprise-grade deployment with validation, healing, and rollback capabilities.

#### Key Features

- **Pre-flight Validation**: Validates configuration before deployment
- **Configuration Healing**: Automatically fixes common issues
- **Enhanced Backup System**: Comprehensive backups with manifests
- **Smart Service Management**: Graceful shutdown and startup
- **Health Verification**: Automatic health checks with retries
- **Automatic Rollback**: Rollback on failure

#### Enhanced Deployment Process

1. **Pre-flight Validation**
   - Run configuration validator with auto-fix
   - Check Docker and Docker Compose availability
   - Validate environment files and Docker configurations

2. **Enhanced Backup**
   - Create comprehensive backup with manifest
   - Include git status and service state
   - Store multiple restore points

3. **Configuration Healing**
   - Fix NODE_ENV settings
   - Remove empty environment overrides
   - Remove obsolete version fields

4. **Safe Update**
   - Stop services gracefully
   - Pull latest changes from git
   - Apply post-update healing

5. **Service Management**
   - Start services with production configuration
   - Wait for health checks to pass
   - Verify deployment success

6. **Verification**
   - Test health endpoint
   - Test version endpoint
   - Show deployment status

7. **Rollback on Failure**
   - Automatic rollback if health checks fail
   - Restore from backup
   - Restart with previous configuration

#### Usage

```bash
# Enhanced deployment with all features
./deploy-update-enhanced.sh

# Configuration validation only
./validate-config.sh

# Configuration validation with auto-fix
./validate-config.sh auto-fix
```

## Service Management

### Check Status
```bash
# View running containers
docker-compose ps

# View logs
docker-compose logs -f gameplan-app
docker-compose logs -f mongodb

# View all logs
docker-compose logs -f
```

### Stop/Start Services
```bash
# Stop all services
docker-compose down

# Start services
docker-compose up -d

# Restart a specific service
docker-compose restart gameplan-app

# Restart all services
docker-compose restart
```

### Update Application

#### Standard Update
```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
```

#### Enhanced Update (Recommended)
```bash
# Use enhanced deployment script
./deploy-update-enhanced.sh
```

## Reverse Proxy Configuration

### Nginx Example
```nginx
server {
    listen 80;
    server_name your-domain.com;

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
    }
}
```

### Apache Example
```apache
<VirtualHost *:80>
    ServerName your-domain.com
    
    ProxyPreserveHost On
    ProxyRequests Off
    ProxyPass / http://localhost:3000/
    ProxyPassReverse / http://localhost:3000/
    
    ProxyPassReverse / http://localhost:3000/
    ProxyPassReverseMatch ^(/.*) http://localhost:3000$1
</VirtualHost>
```

### Traefik Example
```yaml
# docker-compose.override.yml for Traefik
version: '3.8'
services:
  gameplan-app:
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.gameplan.rule=Host(`your-domain.com`)"
      - "traefik.http.routers.gameplan.entrypoints=web"
      - "traefik.http.services.gameplan.loadbalancer.server.port=3000"
```

## Backup and Restore

### Standard Backup
```bash
# Create a backup
./scripts/backup.sh

# Backup with custom location
BACKUP_DIR=/path/to/backups ./scripts/backup.sh
```

### Enhanced Backup (Automatic)
The enhanced deployment system automatically creates backups before each deployment:

```bash
# Backups are stored in config-backups/
ls -la config-backups/

# View backup manifest
cat config-backups/backup_manifest_TIMESTAMP.txt
```

### Restore from Backup

#### Standard Restore
```bash
# List available backups
./scripts/restore.sh

# Restore specific backup
./scripts/restore.sh gameplan_backup_20231214_120000.archive
```

#### Enhanced Restore
```bash
# Restore from enhanced backup
cd config-backups/
tar -xzf config_backup_TIMESTAMP.tar.gz
docker compose restart
```

### Automated Backups
Add to crontab for daily backups:
```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * cd /path/to/GamePlan && ./scripts/backup.sh
```

## Monitoring and Health Checks

### Health Endpoints
```bash
# Check application health
curl http://localhost:3000/api/health

# Check detailed health
curl http://localhost:3000/api/health?detailed=true

# Check version and deployment info
curl http://localhost:3000/api/version

# Check deployment test endpoint
curl http://localhost:3000/api/deployment-test
```

### Container Health
```bash
# Check container health
docker-compose ps

# Check container resource usage
docker stats
```

### Log Management
```bash
# View real-time logs
docker-compose logs -f

# View logs for specific service
docker-compose logs -f gameplan-app

# Limit log output
docker-compose logs --tail=100 gameplan-app

# View logs with timestamps
docker-compose logs -t gameplan-app
```

### Database Management
Access mongo-express at `http://your-server:8081` with credentials:
- Username: `admin` (or your configured `MONGO_EXPRESS_USER`)
- Password: Your configured `MONGO_EXPRESS_PASSWORD`

## Troubleshooting

### Common Issues

#### Application Won't Start
```bash
# Check logs
docker-compose logs gameplan-app

# Check if MongoDB is ready
docker-compose logs mongodb

# Restart services
docker-compose restart

# Check configuration
./validate-config.sh
```

#### Database Connection Issues
```bash
# Verify MongoDB is running
docker-compose ps mongodb

# Check MongoDB logs
docker-compose logs mongodb

# Restart MongoDB
docker-compose restart mongodb

# Check MongoDB connection
docker-compose exec mongodb mongosh --eval "db.adminCommand('ping')"
```

#### Configuration Issues
```bash
# Validate configuration
./validate-config.sh

# Auto-fix configuration issues
./validate-config.sh auto-fix

# Check environment variables
docker-compose config
```

#### Permission Issues
```bash
# Fix file permissions (Linux)
sudo chown -R $USER:$USER .
chmod +x scripts/*.sh
chmod +x *.sh
```

#### Port Conflicts
If port 3000 is already in use:
```bash
# Change port in .env
PORT=3001

# Restart services
docker-compose down
docker-compose up -d
```

#### Enhanced Deployment Issues
```bash
# Check deployment logs
./deploy-update-enhanced.sh 2>&1 | tee deployment.log

# Manual rollback
cd config-backups/
tar -xzf config_backup_TIMESTAMP.tar.gz
docker compose restart
```

### Reset Everything
```bash
# Stop and remove all containers and volumes
docker-compose down -v

# Remove images (optional)
docker-compose down --rmi all

# Clean up Docker system (optional)
docker system prune -a

# Start fresh
docker-compose up -d
docker-compose --profile init up init-admin
```

## Security Considerations

### Essential Security Measures

1. **Change Default Passwords**: Always change all default passwords in `.env`
2. **Secure Environment Files**: Keep `.env` files secure and never commit to version control
3. **Firewall Configuration**: Only expose necessary ports
4. **Regular Updates**: Keep application and Docker images updated
5. **SSL/TLS**: Use HTTPS through reverse proxy
6. **Database Security**: Enable MongoDB authentication in production

### Environment File Protection

The `.gitignore` file protects sensitive configuration:
```
.env.production
docker-compose.production.yml
config-backups/
logs/
```

### Network Security
```bash
# Configure firewall (UFW example)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw enable

# Block direct access to application port if using reverse proxy
# sudo ufw deny 3000/tcp
```

## Performance Tuning

### Resource Limits
Add to `docker-compose.yml` if needed:
```yaml
services:
  gameplan-app:
    deploy:
      resources:
        limits:
          memory: 512M
          cpus: '0.5'
        reservations:
          memory: 256M
          cpus: '0.25'
  
  mongodb:
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
        reservations:
          memory: 512M
          cpus: '0.5'
```

### MongoDB Optimization
For high-traffic deployments:
- Enable MongoDB authentication
- Configure MongoDB indexes (included in init script)
- Set up MongoDB replica sets for high availability
- Configure appropriate MongoDB cache size

### Application Performance
- Enable caching system (see caching documentation)
- Configure appropriate session store
- Use production-optimized Docker images
- Enable compression in reverse proxy

## Deployment Profiles

### Development Profile
```bash
# Development with hot reload
docker-compose -f docker-compose.yml -f docker-compose.development.yml up -d
```

### Production Profile
```bash
# Production deployment
docker-compose -f docker-compose.yml -f docker-compose.production.yml up -d
```

### Tools Profile
```bash
# Enable additional tools (mongo-express, etc.)
docker-compose --profile tools up -d
```

## Version Information

- **GamePlan**: Latest
- **MongoDB**: 7.0
- **Node.js**: 18 Alpine
- **Mongo Express**: 1.0.2
- **Docker Compose**: 2.0+

## Support and Resources

### Documentation
- [Local Development Guide](../development/local-development.md)
- [Ubuntu Deployment Guide](ubuntu-deployment.md)
- [Debian Deployment Guide](debian-deployment.md)
- [Troubleshooting Guide](troubleshooting.md)

### Getting Help
1. Check the logs: `docker-compose logs`
2. Validate configuration: `./validate-config.sh`
3. Review this documentation
4. Check the GitHub repository: https://github.com/cafarnfield/GamePlan
5. Create an issue on GitHub if needed

### Health Check URLs
- **Application Health**: `http://your-server:3000/api/health`
- **Version Information**: `http://your-server:3000/api/version`
- **Configuration Health**: `http://your-server:3000/api/config-health`
- **Deployment Test**: `http://your-server:3000/api/deployment-test`

## Migration Guide

### From Standard to Enhanced Deployment

1. **Backup current setup**:
   ```bash
   ./scripts/backup.sh
   ```

2. **Switch to enhanced deployment**:
   ```bash
   ./deploy-update-enhanced.sh
   ```

3. **Verify deployment**:
   ```bash
   curl http://your-server:3000/api/version
   ```

The enhanced system is backward-compatible and will work with existing configurations while providing additional safety and reliability features.
