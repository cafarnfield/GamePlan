# GamePlan Local Development Setup Script (PowerShell)
# This script sets up a complete local development environment on Windows

param(
    [switch]$Force,
    [switch]$SkipBackup
)

# Set error action preference
$ErrorActionPreference = "Stop"

# Colors for output
function Write-Status {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Blue
}

function Write-Header {
    param([string]$Message)
    Write-Host "🔧 $Message" -ForegroundColor Magenta
}

Write-Host "🚀 GamePlan Local Development Setup" -ForegroundColor Blue
Write-Host "====================================" -ForegroundColor Blue

# Configuration
$BackupDir = "./local-backups"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

# Check if Docker is running
function Test-Docker {
    Write-Header "Checking Docker availability..."
    try {
        docker info | Out-Null
        Write-Status "Docker is running"
        return $true
    }
    catch {
        Write-Error "Docker is not running. Please start Docker Desktop and try again."
        exit 1
    }
}

# Check if Docker Compose is available
function Test-DockerCompose {
    Write-Header "Checking Docker Compose availability..."
    try {
        docker compose version | Out-Null
        Write-Status "Docker Compose is available"
        return $true
    }
    catch {
        Write-Error "Docker Compose is not available. Please install Docker Desktop with Compose support."
        exit 1
    }
}

# Create backup directory
function New-BackupDirectory {
    Write-Header "Creating backup directory..."
    if (!(Test-Path $BackupDir)) {
        New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
    }
    Write-Status "Backup directory ready: $BackupDir"
}

# Setup local environment file
function Set-EnvironmentFile {
    Write-Header "Setting up local environment file..."
    
    if (!(Test-Path ".env.local")) {
        if (Test-Path ".env.local.example") {
            Copy-Item ".env.local.example" ".env.local"
            Write-Status "Created .env.local from example file"
            Write-Info "Please review and customize .env.local for your local setup"
        }
        else {
            Write-Warning ".env.local.example not found. Creating basic .env.local"
            $basicEnv = @"
# Basic local development configuration
PORT=3000
NODE_ENV=development
MONGO_ROOT_PASSWORD=local_dev_root_password
MONGO_PASSWORD=local_dev_app_password
SESSION_SECRET=local_development_session_secret_not_for_production
ADMIN_EMAIL=admin@localhost.dev
ADMIN_PASSWORD=LocalAdmin123!
ADMIN_NAME=Local Development Admin
ADMIN_NICKNAME=DevAdmin
RAWG_API_KEY=3963501b74354e0688413453cb8c6bc4
MONGO_EXPRESS_PORT=8081
MONGO_EXPRESS_USER=admin
MONGO_EXPRESS_PASSWORD=local_mongo_express_password
LOG_LEVEL=debug
LOG_CONSOLE=true
AUTO_LOGIN_ADMIN=true
"@
            $basicEnv | Out-File -FilePath ".env.local" -Encoding UTF8
            Write-Status "Created basic .env.local file"
        }
    }
    else {
        Write-Status ".env.local already exists"
    }
}

# Install dependencies
function Install-Dependencies {
    Write-Header "Installing Node.js dependencies..."
    
    if (Test-Path "package.json") {
        try {
            npm --version | Out-Null
            npm install
            Write-Status "Dependencies installed with npm"
        }
        catch {
            Write-Warning "npm not found. Please install Node.js and npm"
        }
    }
    else {
        Write-Warning "package.json not found"
    }
}

# Build Docker images
function Build-Images {
    Write-Header "Building Docker images..."
    
    try {
        if (Test-Path "docker-compose.local.yml") {
            docker compose -f docker-compose.yml -f docker-compose.local.yml build
            Write-Status "Docker images built successfully"
        }
        else {
            Write-Warning "docker-compose.local.yml not found, using default configuration"
            docker compose build
            Write-Status "Docker images built with default configuration"
        }
    }
    catch {
        Write-Error "Failed to build Docker images: $_"
        exit 1
    }
}

# Start services
function Start-Services {
    Write-Header "Starting local development services..."
    
    try {
        if (Test-Path "docker-compose.local.yml") {
            docker compose -f docker-compose.yml -f docker-compose.local.yml up -d
            Write-Status "Services started with local development configuration"
        }
        else {
            docker compose up -d
            Write-Status "Services started with default configuration"
        }
    }
    catch {
        Write-Error "Failed to start services: $_"
        exit 1
    }
}

# Wait for services to be healthy
function Wait-ForServices {
    Write-Header "Waiting for services to become healthy..."
    
    $maxAttempts = 30
    $attempt = 1
    
    while ($attempt -le $maxAttempts) {
        $status = docker compose ps --format json | ConvertFrom-Json
        $healthyServices = $status | Where-Object { $_.Health -eq "healthy" -or $_.State -eq "running" }
        
        if ($healthyServices.Count -gt 0) {
            Write-Status "Services are healthy"
            return
        }
        
        Write-Info "Attempt $attempt/$maxAttempts - waiting for services..."
        Start-Sleep -Seconds 5
        $attempt++
    }
    
    Write-Warning "Services may still be starting. Check with 'docker compose ps'"
}

# Initialize admin user
function Initialize-Admin {
    Write-Header "Initializing admin user..."
    
    try {
        if (Test-Path "docker-compose.local.yml") {
            docker compose -f docker-compose.yml -f docker-compose.local.yml run --rm init-admin
        }
        else {
            docker compose run --rm init-admin
        }
        Write-Status "Admin user initialization completed"
    }
    catch {
        Write-Warning "Admin initialization may have failed, but continuing..."
    }
}

# Show final status
function Show-Status {
    Write-Header "Final setup status..."
    
    Write-Host ""
    Write-Status "🎉 Local development environment setup complete!"
    Write-Host ""
    Write-Info "Application URL: http://localhost:3000"
    Write-Info "Mongo Express: http://localhost:8081"
    Write-Info "Admin Login: Check your .env.local file for credentials"
    Write-Host ""
    Write-Info "Useful commands:"
    Write-Host "  • View logs: docker compose logs -f"
    Write-Host "  • Stop services: docker compose down"
    Write-Host "  • Restart services: docker compose restart"
    Write-Host "  • Backup database: .\backup-local.ps1"
    Write-Host "  • Reset environment: .\reset-local.ps1"
    Write-Host ""
    
    # Show running services
    Write-Info "Running services:"
    if (Test-Path "docker-compose.local.yml") {
        docker compose -f docker-compose.yml -f docker-compose.local.yml ps
    }
    else {
        docker compose ps
    }
}

# Main execution
function Main {
    Write-Info "Starting GamePlan local development setup..."
    Write-Host ""
    
    Test-Docker
    Test-DockerCompose
    New-BackupDirectory
    Set-EnvironmentFile
    Install-Dependencies
    Build-Images
    Start-Services
    Wait-ForServices
    Initialize-Admin
    Show-Status
    
    Write-Host ""
    Write-Status "Setup completed successfully! 🚀"
}

# Run main function
try {
    Main
}
catch {
    Write-Error "Setup failed: $_"
    exit 1
}
