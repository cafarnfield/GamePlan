# GamePlan Ubuntu Quick Start Guide

**One-command deployment for Ubuntu Server 22.04 LTS**

## 🚀 Instant Deployment

```bash
curl -fsSL https://raw.githubusercontent.com/cafarnfield/GamePlan/main/scripts/ubuntu-install.sh | bash
```

**That's it!** Your GamePlan application will be running at `http://your-server-ip:3000`

---

## 📋 What This Does

✅ **System Setup**
- Updates Ubuntu packages
- Installs Docker & Docker Compose
- Configures system requirements

✅ **Security Configuration**
- Sets up UFW firewall
- Generates secure passwords
- Configures user permissions

✅ **Application Deployment**
- Clones GamePlan repository
- Configures environment variables
- Deploys with Docker Compose
- Creates admin user

✅ **System Integration**
- Creates systemd service
- Enables auto-start on boot
- Sets up health monitoring

---

## 🔐 SSL Setup (Optional)

After basic deployment, add SSL certificate:

```bash
cd GamePlan
chmod +x scripts/ssl-setup.sh
./scripts/ssl-setup.sh your-domain.com
```

**With email notifications:**
```bash
./scripts/ssl-setup.sh -e admin@yourdomain.com your-domain.com
```

**Include www subdomain:**
```bash
./scripts/ssl-setup.sh -w -e admin@yourdomain.com your-domain.com
```

---

## 📊 System Requirements

- **OS**: Ubuntu 22.04 LTS (recommended)
- **RAM**: 2GB minimum, 4GB recommended
- **Storage**: 20GB minimum, 40GB recommended
- **Network**: Internet connection required
- **Access**: sudo privileges required

---

## 🎯 Access Information

After deployment:

- **Application**: `http://your-server-ip:3000`
- **Admin Login**: Check `~/gameplan-credentials.txt`
- **Health Check**: `http://your-server-ip:3000/api/health`
- **Database Admin**: `http://your-server-ip:8081` (optional)

---

## 🔧 Useful Commands

```bash
# Check status
docker compose ps
curl http://localhost:3000/api/health

# View logs
docker compose logs -f gameplan-app

# Restart application
sudo systemctl restart gameplan

# Update application
cd GamePlan
git pull
docker compose down
docker compose up -d

# Stop application
sudo systemctl stop gameplan

# Start application
sudo systemctl start gameplan
```

---

## 🚨 Troubleshooting

**Application not accessible?**
```bash
# Check firewall
sudo ufw status

# Check containers
docker compose ps

# Check logs
docker compose logs gameplan-app
```

**SSL issues?**
```bash
# Check certificate
sudo certbot certificates

# Test Nginx config
sudo nginx -t

# Restart Nginx
sudo systemctl restart nginx
```

**Need help?**
- Full documentation: [UBUNTU_DEPLOYMENT.md](UBUNTU_DEPLOYMENT.md)
- Docker guide: [DEPLOYMENT.md](DEPLOYMENT.md)
- GitHub issues: [GamePlan Issues](https://github.com/cafarnfield/GamePlan/issues)

---

## 🎉 Next Steps

1. **Update admin email** in `.env` file
2. **Configure domain name** (optional)
3. **Set up SSL certificate** for HTTPS
4. **Configure backup schedule**
5. **Set up monitoring alerts**

**Your GamePlan application is ready to use! 🚀**
