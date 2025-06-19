# GamePlan Local Development Guide

This guide provides comprehensive instructions for setting up and managing your local GamePlan development environment.

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose installed
- Node.js and npm (optional, for direct development)
- Git

### One-Command Setup
```bash
./setup-local.sh
```

This script will:
- ✅ Check Docker availability
- ✅ Create local configuration files
- ✅ Install dependencies
- ✅ Build Docker images
- ✅ Start all services
- ✅ Initialize admin user
- ✅ Show access URLs

## 📁 File Structure

### Configuration Files
```
.env.local.example          # Template for local environment variables
.env.local                  # Your local environment (auto-created, git-ignored)
docker-compose.local.yml    # Local development overrides
docker-compose.override.yml # Default development overrides
```

### Scripts
```
setup-local.sh              # Complete environment setup
backup-local.sh             # Backup local environment
reset-local.sh              # Reset environment to clean state
restore-local.sh            # Restore from backup (if created)
```

### Directories
```
local-backups/              # Local backup storage (git-ignored)
logs/                       # Application logs
node_modules/               # Node.js dependencies
```

## 🔧 Configuration

### Environment Variables

Copy `.env.local.example` to `.env.local` and customize:

```bash
cp .env.local.example .env.local
```

Key settings for local development:
- `NODE_ENV=development` - Enables development features
- `AUTO_LOGIN_ADMIN=true` - Automatic admin login for convenience
- `LOG_LEVEL=debug` - Verbose logging for debugging
- `PORT=3000` - Application port

### Docker Compose Configurations

The system uses layered Docker Compose files:

1. **`docker-compose.yml`** - Base configuration
2. **`docker-compose.local.yml`** - Local development overrides
3. **`docker-compose.override.yml`** - Default development settings

## 🛠️ Development Workflow

### Starting Development
```bash
# Complete setup (first time or after reset)
./setup-local.sh

# Or manually start services
docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
```

### Daily Development
```bash
# View logs
docker compose logs -f

# Restart a specific service
docker compose restart gameplan-app

# Stop all services
docker compose down

# Rebuild after code changes
docker compose up -d --build
```

### Database Management
```bash
# Access MongoDB directly
docker compose exec mongodb mongosh

# Access Mongo Express (Web UI)
# Visit: http://localhost:8081
# Credentials: Check your .env.local file
```

## 🗄️ Backup & Restore

### Creating Backups
```bash
# Create full backup (config + database)
./backup-local.sh

# Manual configuration backup
tar -czf backup.tar.gz .env.local docker-compose.local.yml
```

### Restoring Backups
```bash
# List available backups
ls -la local-backups/

# Restore from backup (if restore script exists)
./restore-local.sh [timestamp]

# Manual restore
tar -xzf local-backups/config_backup_[timestamp].tar.gz
```

## 🔄 Environment Reset

### Complete Reset
```bash
./reset-local.sh
```

This will:
- Create automatic backup
- Stop and remove all containers
- Remove Docker volumes and networks
- Optionally remove images and node_modules
- Clean temporary files

### Partial Reset
```bash
# Stop services only
docker compose down

# Remove volumes (loses database data)
docker compose down -v

# Remove everything including images
docker compose down -v --rmi all
```

## 🌐 Access Points

After setup, access your application at:

- **Main Application**: http://localhost:3000
- **Mongo Express**: http://localhost:8081
- **API Health Check**: http://localhost:3000/api/health

### Default Credentials

Check your `.env.local` file for:
- Admin email and password
- Mongo Express credentials
- Database passwords

## 🐛 Debugging

### Enable Debug Mode
```bash
# In .env.local
NODE_ENV=development
LOG_LEVEL=debug
LOG_CONSOLE=true
```

### Debug with Node.js Inspector
```bash
# The local setup exposes port 9229 for debugging
# Connect your IDE debugger to localhost:9229
```

### View Logs
```bash
# All services
docker compose logs -f

# Specific service
docker compose logs -f gameplan-app

# Database logs
docker compose logs -f mongodb
```

## 🔍 Troubleshooting

### Common Issues

#### Port Already in Use
```bash
# Check what's using the port
lsof -i :3000

# Kill the process or change PORT in .env.local
```

#### Database Connection Issues
```bash
# Check MongoDB status
docker compose ps mongodb

# Restart MongoDB
docker compose restart mongodb

# Check MongoDB logs
docker compose logs mongodb
```

#### Permission Issues
```bash
# Make scripts executable
chmod +x *.sh

# Fix file ownership (Linux/Mac)
sudo chown -R $USER:$USER .
```

#### Docker Issues
```bash
# Clean Docker system
docker system prune -f

# Reset Docker completely
./reset-local.sh
```

### Getting Help

1. Check the logs: `docker compose logs -f`
2. Verify configuration: `cat .env.local`
3. Check service status: `docker compose ps`
4. Reset environment: `./reset-local.sh`

## 🚀 Advanced Usage

### Custom Configuration

Create additional override files:
```bash
# For specific features
docker-compose.feature.yml

# Use with
docker compose -f docker-compose.yml -f docker-compose.local.yml -f docker-compose.feature.yml up
```

### Development with Hot Reload

The local configuration includes:
- Volume mounting for live code changes
- Nodemon for automatic restarts
- Debug port exposure

### Database Seeding

```bash
# Run custom initialization
docker compose run --rm gameplan-app node scripts/seed-data.js
```

### Testing

```bash
# Run tests in container
docker compose run --rm gameplan-app npm test

# Run tests locally (if Node.js installed)
npm test
```

## 📝 Best Practices

### Development Workflow
1. Always use `./setup-local.sh` for initial setup
2. Create backups before major changes
3. Use `docker compose logs -f` to monitor issues
4. Reset environment when things get messy

### Configuration Management
1. Never commit `.env.local` to git
2. Update `.env.local.example` when adding new variables
3. Document configuration changes

### Database Management
1. Regular backups with `./backup-local.sh`
2. Use Mongo Express for database inspection
3. Don't rely on local data for important information

## 🔗 Related Documentation

- [Main README](./README.md) - Project overview
- [Deployment Guide](./DEPLOYMENT.md) - Production deployment
- [API Documentation](./docs/) - API reference

## 🆘 Support

If you encounter issues:
1. Check this guide first
2. Review the troubleshooting section
3. Check Docker and Node.js versions
4. Reset environment as last resort

---

**Happy coding! 🎉**
