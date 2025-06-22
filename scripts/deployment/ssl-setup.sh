#!/bin/bash

# GamePlan SSL Setup Script
# This script sets up SSL certificates using Let's Encrypt for GamePlan

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

info() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   error "This script should not be run as root. Please run as a regular user with sudo privileges."
   exit 1
fi

# Function to display usage
usage() {
    cat << EOF
Usage: $0 [OPTIONS] DOMAIN

Setup SSL certificates for GamePlan using Let's Encrypt

ARGUMENTS:
    DOMAIN          Your domain name (e.g., gameplan.example.com)

OPTIONS:
    -e, --email     Email address for Let's Encrypt notifications
    -w, --www       Include www subdomain (e.g., www.gameplan.example.com)
    -t, --test      Use Let's Encrypt staging environment (for testing)
    -f, --force     Force certificate renewal even if valid
    -h, --help      Show this help message

EXAMPLES:
    $0 gameplan.example.com
    $0 -e admin@example.com -w gameplan.example.com
    $0 --test --email admin@example.com gameplan.example.com

PREREQUISITES:
    - Domain must point to this server's IP address
    - Nginx must be installed and configured
    - Port 80 and 443 must be accessible from the internet
    - GamePlan should be running on port 3000

EOF
}

# Parse command line arguments
DOMAIN=""
EMAIL=""
INCLUDE_WWW=false
TEST_MODE=false
FORCE_RENEWAL=false

while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--email)
            EMAIL="$2"
            shift 2
            ;;
        -w|--www)
            INCLUDE_WWW=true
            shift
            ;;
        -t|--test)
            TEST_MODE=true
            shift
            ;;
        -f|--force)
            FORCE_RENEWAL=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        -*)
            error "Unknown option $1"
            usage
            exit 1
            ;;
        *)
            if [[ -z "$DOMAIN" ]]; then
                DOMAIN="$1"
            else
                error "Multiple domains specified. Only one domain is supported."
                exit 1
            fi
            shift
            ;;
    esac
done

# Validate domain
if [[ -z "$DOMAIN" ]]; then
    error "Domain is required"
    usage
    exit 1
fi

# Validate domain format
if ! [[ "$DOMAIN" =~ ^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$ ]]; then
    error "Invalid domain format: $DOMAIN"
    exit 1
fi

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if Nginx is installed
    if ! command -v nginx &> /dev/null; then
        error "Nginx is not installed. Please install Nginx first."
        exit 1
    fi
    
    # Check if Nginx is running
    if ! systemctl is-active --quiet nginx; then
        error "Nginx is not running. Please start Nginx first."
        exit 1
    fi
    
    # Check if GamePlan is running
    if ! curl -s http://localhost:3000/api/health &> /dev/null; then
        error "GamePlan is not running on port 3000. Please start GamePlan first."
        exit 1
    fi
    
    # Check if domain resolves to this server
    SERVER_IP=$(curl -s ifconfig.me 2>/dev/null || curl -s ipinfo.io/ip 2>/dev/null || echo "unknown")
    DOMAIN_IP=$(dig +short "$DOMAIN" 2>/dev/null || echo "unknown")
    
    if [[ "$SERVER_IP" != "unknown" && "$DOMAIN_IP" != "unknown" ]]; then
        if [[ "$SERVER_IP" == "$DOMAIN_IP" ]]; then
            log "Domain DNS check passed: $DOMAIN -> $DOMAIN_IP"
        else
            warn "Domain DNS mismatch: $DOMAIN -> $DOMAIN_IP, Server IP: $SERVER_IP"
            warn "SSL setup may fail if domain doesn't point to this server"
        fi
    else
        warn "Could not verify domain DNS resolution"
    fi
    
    log "Prerequisites check completed"
}

# Install Certbot
install_certbot() {
    log "Installing Certbot..."
    
    # Update package list
    sudo apt update
    
    # Install Certbot and Nginx plugin
    sudo apt install -y certbot python3-certbot-nginx
    
    log "Certbot installation completed"
}

# Setup Nginx configuration
setup_nginx() {
    log "Setting up Nginx configuration for $DOMAIN..."
    
    # Create Nginx configuration from template
    NGINX_CONFIG="/etc/nginx/sites-available/gameplan"
    
    if [[ -f "$NGINX_CONFIG" ]]; then
        log "Backing up existing Nginx configuration..."
        sudo cp "$NGINX_CONFIG" "$NGINX_CONFIG.backup.$(date +%Y%m%d_%H%M%S)"
    fi
    
    # Create basic HTTP configuration
    sudo tee "$NGINX_CONFIG" > /dev/null << EOF
server {
    listen 80;
    server_name $DOMAIN$([ "$INCLUDE_WWW" = true ] && echo " www.$DOMAIN");
    
    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;

    # Rate limiting
    limit_req_zone \$binary_remote_addr zone=gameplan:10m rate=10r/s;
    limit_req zone=gameplan burst=20 nodelay;

    # Client settings
    client_max_body_size 10M;

    # Proxy to GamePlan application
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_cache_bypass \$http_upgrade;
        proxy_read_timeout 86400;
    }

    # Health check endpoint
    location /api/health {
        proxy_pass http://localhost:3000/api/health;
        access_log off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }

    # Static files caching
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)\$ {
        proxy_pass http://localhost:3000;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }

    # Block access to sensitive files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Logging
    access_log /var/log/nginx/gameplan_access.log;
    error_log /var/log/nginx/gameplan_error.log;
}
EOF
    
    # Enable site
    sudo ln -sf /etc/nginx/sites-available/gameplan /etc/nginx/sites-enabled/
    
    # Remove default site if it exists
    sudo rm -f /etc/nginx/sites-enabled/default
    
    # Test Nginx configuration
    if sudo nginx -t; then
        log "Nginx configuration is valid"
        sudo systemctl reload nginx
    else
        error "Nginx configuration is invalid"
        exit 1
    fi
    
    log "Nginx configuration completed"
}

# Generate DH parameters
generate_dhparam() {
    log "Generating DH parameters (this may take a few minutes)..."
    
    if [[ ! -f /etc/nginx/dhparam.pem ]]; then
        sudo openssl dhparam -out /etc/nginx/dhparam.pem 2048
        log "DH parameters generated"
    else
        log "DH parameters already exist"
    fi
}

# Obtain SSL certificate
obtain_certificate() {
    log "Obtaining SSL certificate for $DOMAIN..."
    
    # Build certbot command
    CERTBOT_CMD="sudo certbot --nginx"
    
    # Add domain
    CERTBOT_CMD="$CERTBOT_CMD -d $DOMAIN"
    if [[ "$INCLUDE_WWW" = true ]]; then
        CERTBOT_CMD="$CERTBOT_CMD -d www.$DOMAIN"
    fi
    
    # Add email if provided
    if [[ -n "$EMAIL" ]]; then
        CERTBOT_CMD="$CERTBOT_CMD --email $EMAIL"
    else
        CERTBOT_CMD="$CERTBOT_CMD --register-unsafely-without-email"
    fi
    
    # Add test mode if specified
    if [[ "$TEST_MODE" = true ]]; then
        CERTBOT_CMD="$CERTBOT_CMD --test-cert"
        warn "Using Let's Encrypt staging environment (test certificates)"
    fi
    
    # Add force renewal if specified
    if [[ "$FORCE_RENEWAL" = true ]]; then
        CERTBOT_CMD="$CERTBOT_CMD --force-renewal"
    fi
    
    # Add non-interactive flags
    CERTBOT_CMD="$CERTBOT_CMD --non-interactive --agree-tos --redirect"
    
    # Execute certbot command
    log "Running: $CERTBOT_CMD"
    if eval "$CERTBOT_CMD"; then
        log "SSL certificate obtained successfully"
    else
        error "Failed to obtain SSL certificate"
        exit 1
    fi
}

# Setup automatic renewal
setup_auto_renewal() {
    log "Setting up automatic certificate renewal..."
    
    # Test automatic renewal
    if sudo certbot renew --dry-run; then
        log "Automatic renewal test passed"
    else
        warn "Automatic renewal test failed"
    fi
    
    # Add cron job for renewal (if not already exists)
    CRON_JOB="0 12 * * * /usr/bin/certbot renew --quiet"
    if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
        (crontab -l 2>/dev/null; echo "$CRON_JOB") | crontab -
        log "Added cron job for automatic renewal"
    else
        log "Cron job for automatic renewal already exists"
    fi
    
    log "Automatic renewal setup completed"
}

# Update firewall
update_firewall() {
    log "Updating firewall rules..."
    
    # Allow HTTPS
    sudo ufw allow 443/tcp
    
    # Remove direct access to port 3000 (force through Nginx)
    if sudo ufw status | grep -q "3000/tcp"; then
        sudo ufw delete allow 3000/tcp
        log "Removed direct access to port 3000"
    fi
    
    log "Firewall rules updated"
}

# Verify SSL setup
verify_ssl() {
    log "Verifying SSL setup..."
    
    # Wait a moment for Nginx to reload
    sleep 5
    
    # Test HTTPS connection
    if curl -s -I "https://$DOMAIN" | grep -q "HTTP/"; then
        log "HTTPS connection test passed"
    else
        warn "HTTPS connection test failed"
    fi
    
    # Test HTTP to HTTPS redirect
    if curl -s -I "http://$DOMAIN" | grep -q "301\|302"; then
        log "HTTP to HTTPS redirect test passed"
    else
        warn "HTTP to HTTPS redirect test failed"
    fi
    
    # Test SSL certificate
    if openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
        log "SSL certificate verification passed"
    else
        warn "SSL certificate verification failed"
    fi
    
    log "SSL verification completed"
}

# Display results
display_results() {
    cat << EOF

${GREEN}🔒 SSL Setup Completed Successfully! 🔒${NC}

${BLUE}SSL Information:${NC}
- Domain: $DOMAIN$([ "$INCLUDE_WWW" = true ] && echo ", www.$DOMAIN")
- Certificate Type: $([ "$TEST_MODE" = true ] && echo "Test (Staging)" || echo "Production")
- Auto-renewal: Enabled (daily check at 12:00 PM)

${BLUE}Access URLs:${NC}
- HTTPS: https://$DOMAIN
- HTTP: http://$DOMAIN (redirects to HTTPS)
$([ "$INCLUDE_WWW" = true ] && echo "- HTTPS WWW: https://www.$DOMAIN")

${BLUE}Certificate Details:${NC}
- Certificate files: /etc/letsencrypt/live/$DOMAIN/
- Nginx configuration: /etc/nginx/sites-available/gameplan
- Log files: /var/log/nginx/gameplan_*.log

${BLUE}Useful Commands:${NC}
- Check certificate: sudo certbot certificates
- Renew certificate: sudo certbot renew
- Test renewal: sudo certbot renew --dry-run
- Check Nginx config: sudo nginx -t
- Reload Nginx: sudo systemctl reload nginx

${BLUE}Security Features Enabled:${NC}
✅ SSL/TLS encryption (HTTPS)
✅ HTTP to HTTPS redirect
✅ Security headers (HSTS, XSS protection, etc.)
✅ Rate limiting
✅ Automatic certificate renewal

$([ "$TEST_MODE" = true ] && echo "${YELLOW}Note: Test certificates are not trusted by browsers. Remove --test flag for production.${NC}")

${GREEN}Your GamePlan application is now secured with SSL! 🚀${NC}

EOF
}

# Main function
main() {
    log "Starting SSL setup for GamePlan..."
    
    check_prerequisites
    install_certbot
    setup_nginx
    generate_dhparam
    obtain_certificate
    setup_auto_renewal
    update_firewall
    verify_ssl
    display_results
    
    log "SSL setup completed successfully!"
}

# Handle script interruption
trap 'error "SSL setup interrupted"; exit 1' INT TERM

# Run main function
main "$@"
