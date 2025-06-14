# GamePlan Docker Deployment Guide

This guide will help you deploy GamePlan using Docker Compose on any Linux server.

## Prerequisites

- Docker Engine (20.10.0 or later)
- Docker Compose (2.0.0 or later)
- At least 2GB RAM
- At least 5GB free disk space

## Quick Start

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

## Detailed Setup

### 1. Environment Configuration

Copy `.env.example` to `.env` and configure the following required variables:

#### Essential Settings
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
```

#### API Keys (Optional but Recommended)
```bash
# Steam API Key (for enhanced game integration)
STEAM_API_KEY=your_steam_api_key_here

# RAWG API Key (already provided, but you can use your own)
RAWG_API_KEY=3963501b74354e0688413453cb8c6bc4
```

#### Database Admin Interface
```bash
# Mongo Express credentials
MONGO_EXPRESS_PASSWORD=your_mongo_express_password
```

### 2. Deployment Options

#### Production Deployment
```bash
# Start all services
docker-compose up -d

# Initialize admin user (run once)
docker-compose --profile init up init-admin

# Enable database admin interface (optional)
docker-compose --profile tools up -d mongo-express
```

#### Development Deployment
```bash
# Development mode with hot reload and auto-admin login
docker-compose -f docker-compose.yml -f docker-compose.override.yml up -d

# Initialize admin user
docker-compose --profile init up init-admin
```

### 3. Service Management

#### Check Status
```bash
# View running containers
docker-compose ps

# View logs
docker-compose logs -f gameplan-app
docker-compose logs -f mongodb
```

#### Stop/Start Services
```bash
# Stop all services
docker-compose down

# Start services
docker-compose up -d

# Restart a specific service
docker-compose restart gameplan-app
```

#### Update Application
```bash
# Pull latest changes
git pull

# Rebuild and restart
docker-compose down
docker-compose build --no-cache
docker-compose up -d
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

### Create Backup
```bash
# Create a backup
./scripts/backup.sh

# Backup with custom location
BACKUP_DIR=/path/to/backups ./scripts/backup.sh
```

### Restore from Backup
```bash
# List available backups
./scripts/restore.sh

# Restore specific backup
./scripts/restore.sh gameplan_backup_20231214_120000.archive
```

### Automated Backups
Add to crontab for daily backups:
```bash
# Edit crontab
crontab -e

# Add daily backup at 2 AM
0 2 * * * cd /path/to/GamePlan && ./scripts/backup.sh
```

## Monitoring and Maintenance

### Health Checks
```bash
# Check application health
curl http://localhost:3000/api/health

# Check container health
docker-compose ps
```

### Log Management
```bash
# View real-time logs
docker-compose logs -f

# View logs for specific service
docker-compose logs -f gameplan-app

# Limit log output
docker-compose logs --tail=100 gameplan-app
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
```

#### Database Connection Issues
```bash
# Verify MongoDB is running
docker-compose ps mongodb

# Check MongoDB logs
docker-compose logs mongodb

# Restart MongoDB
docker-compose restart mongodb
```

#### Permission Issues
```bash
# Fix file permissions (Linux)
sudo chown -R $USER:$USER .
chmod +x scripts/*.sh
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

### Reset Everything
```bash
# Stop and remove all containers and volumes
docker-compose down -v

# Remove images (optional)
docker-compose down --rmi all

# Start fresh
docker-compose up -d
docker-compose --profile init up init-admin
```

## Security Considerations

1. **Change Default Passwords**: Always change all default passwords in `.env`
2. **Firewall**: Only expose necessary ports (3000 for app, 8081 for mongo-express if needed)
3. **Updates**: Regularly update the application and Docker images
4. **Backups**: Implement regular automated backups
5. **SSL/TLS**: Use HTTPS through your reverse proxy
6. **Environment File**: Keep `.env` secure and never commit it to version control

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
  
  mongodb:
    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'
```

### MongoDB Optimization
For high-traffic deployments, consider:
- Enabling MongoDB authentication
- Setting up MongoDB replica sets
- Configuring MongoDB indexes (already included in init script)

## Support

For issues and questions:
1. Check the logs: `docker-compose logs`
2. Review this documentation
3. Check the GitHub repository: https://github.com/cafarnfield/GamePlan
4. Create an issue on GitHub if needed

## Version Information

- GamePlan: Latest
- MongoDB: 7.0
- Node.js: 18 Alpine
- Mongo Express: 1.0.2
