# GamePlan Local Development Backup Script (PowerShell)
# This script creates backups of your local development environment

param(
    [switch]$ConfigOnly,
    [switch]$DatabaseOnly
)

# Set error action preference
$ErrorActionPreference = "Continue"

# Colors for output
function Write-Status {
    param([string]$Message)
    Write-Host "✅ $Message" -ForegroundColor Green
}

function Write-Info {
    param([string]$Message)
    Write-Host "ℹ️  $Message" -ForegroundColor Blue
}

function Write-Warning {
    param([string]$Message)
    Write-Host "⚠️  $Message" -ForegroundColor Yellow
}

function Write-Error {
    param([string]$Message)
    Write-Host "❌ $Message" -ForegroundColor Red
}

# Configuration
$BackupDir = "./local-backups"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$ConfigBackupFile = "$BackupDir/config_backup_$Timestamp.zip"
$DbBackupDir = "$BackupDir/database_backup_$Timestamp"

Write-Host "🗄️  GamePlan Local Development Backup" -ForegroundColor Blue
Write-Host "=====================================" -ForegroundColor Blue

# Create backup directory if it doesn't exist
if (!(Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

Write-Info "Starting local development backup..."

# Backup configuration files
function Backup-Config {
    Write-Info "Backing up configuration files..."
    
    $filesToBackup = @()
    
    # Check which files exist and add them to backup
    if (Test-Path ".env.local") { $filesToBackup += ".env.local" }
    if (Test-Path "docker-compose.local.yml") { $filesToBackup += "docker-compose.local.yml" }
    if (Test-Path "docker-compose.override.yml") { $filesToBackup += "docker-compose.override.yml" }
    if (Test-Path "docker-compose.yml") { $filesToBackup += "docker-compose.yml" }
    
    if ($filesToBackup.Count -gt 0) {
        try {
            # Use PowerShell's Compress-Archive
            Compress-Archive -Path $filesToBackup -DestinationPath $ConfigBackupFile -Force
            Write-Status "Configuration backup created: $ConfigBackupFile"
        }
        catch {
            Write-Error "Failed to create configuration backup: $_"
        }
    }
    else {
        Write-Warning "No configuration files found to backup"
    }
}

# Backup database
function Backup-Database {
    Write-Info "Backing up local database..."
    
    # Check if MongoDB container is running
    try {
        $mongoStatus = docker compose ps --format json | ConvertFrom-Json | Where-Object { $_.Service -eq "mongodb" -and $_.State -eq "running" }
        
        if ($mongoStatus) {
            # Load environment variables from .env.local
            $envVars = @{}
            if (Test-Path ".env.local") {
                Get-Content ".env.local" | ForEach-Object {
                    if ($_ -match "^([^#][^=]+)=(.*)$") {
                        $envVars[$matches[1]] = $matches[2]
                    }
                }
            }
            
            $mongoPassword = if ($envVars["MONGO_ROOT_PASSWORD"]) { $envVars["MONGO_ROOT_PASSWORD"] } else { "local_dev_root_password" }
            
            # Create database backup using mongodump
            try {
                docker compose exec -T mongodb mongodump --host localhost --port 27017 --username admin --password $mongoPassword --authenticationDatabase admin --db gameplan --out /backups/database_backup_$Timestamp
                Write-Status "Database backup created: $DbBackupDir"
            }
            catch {
                Write-Warning "Direct mongodump failed, trying alternative method..."
                
                # Alternative: use docker run with network
                try {
                    docker run --rm --network gameplan_gameplan-network -v "${PWD}/local-backups:/backups" mongo:7.0 mongodump --host gameplan-mongodb --port 27017 --username admin --password $mongoPassword --authenticationDatabase admin --db gameplan --out /backups/database_backup_$Timestamp
                    Write-Status "Database backup created: $DbBackupDir"
                }
                catch {
                    Write-Error "Database backup failed. Make sure MongoDB is running."
                    return $false
                }
            }
        }
        else {
            Write-Warning "MongoDB container is not running. Skipping database backup."
            Write-Info "Start your local environment with: .\setup-local.ps1"
            return $false
        }
    }
    catch {
        Write-Error "Failed to check MongoDB status: $_"
        return $false
    }
    
    return $true
}

# Create backup manifest
function New-BackupManifest {
    Write-Info "Creating backup manifest..."
    
    $manifestFile = "$BackupDir/backup_manifest_$Timestamp.txt"
    
    $manifest = @"
GamePlan Local Development Backup Manifest
==========================================
Backup Date: $(Get-Date)
Timestamp: $Timestamp

Configuration Backup: $(Split-Path $ConfigBackupFile -Leaf)
Database Backup: $(Split-Path $DbBackupDir -Leaf)

Files included in configuration backup:
$(if (Test-Path $ConfigBackupFile) { 
    try {
        (Get-ChildItem -Path $ConfigBackupFile | Select-Object -ExpandProperty Name) -join "`n"
    } catch {
        "Unable to list archive contents"
    }
} else { 
    "No configuration backup created" 
})

Environment:
- PowerShell Version: $($PSVersionTable.PSVersion)
- Docker Version: $(try { docker --version } catch { "Not available" })
- Docker Compose Version: $(try { docker compose version } catch { "Not available" })

Docker Services Status:
$(try { docker compose ps } catch { "No services running" })
"@

    try {
        $manifest | Out-File -FilePath $manifestFile -Encoding UTF8
        Write-Status "Backup manifest created: $manifestFile"
    }
    catch {
        Write-Warning "Failed to create backup manifest: $_"
    }
}

# Show backup summary
function Show-Summary {
    Write-Info "Backup Summary:"
    Write-Host ""
    Write-Status "Backup completed!"
    Write-Host ""
    Write-Info "Backup files created:"
    
    try {
        Get-ChildItem -Path "$BackupDir/*$Timestamp*" | ForEach-Object {
            Write-Host "  $($_.Name) - $($_.Length) bytes"
        }
    }
    catch {
        Write-Warning "No backup files found"
    }
    
    Write-Host ""
    Write-Info "To restore this backup:"
    Write-Host "  1. Stop current services: docker compose down"
    Write-Host "  2. Restore config: Expand-Archive $ConfigBackupFile -Force"
    Write-Host "  3. Restore database: .\restore-local.ps1 $Timestamp"
    Write-Host "  4. Restart services: .\setup-local.ps1"
    Write-Host ""
}

# Main execution
function Main {
    if ($ConfigOnly) {
        Backup-Config
    }
    elseif ($DatabaseOnly) {
        Backup-Database
    }
    else {
        Backup-Config
        Backup-Database
    }
    
    New-BackupManifest
    Show-Summary
}

# Run main function
try {
    Main
}
catch {
    Write-Error "Backup failed: $_"
    exit 1
}
