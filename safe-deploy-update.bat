@echo off
setlocal enabledelayedexpansion

REM GamePlan Safe Deployment Update Script (Windows Version)
REM This script safely updates from GitHub without killing the running application

echo.
echo ================================
echo GamePlan Safe Deployment Update
echo ================================
echo.

REM Check if we're in a git repository
git status >nul 2>&1
if errorlevel 1 (
    echo ERROR: Not in a git repository or git not available
    pause
    exit /b 1
)

REM Check if Docker is available
docker --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Docker not available or not running
    pause
    exit /b 1
)

echo [INFO] Starting safe deployment update process...
echo.

REM Create backup directory
if not exist "deployment-backups" mkdir deployment-backups

REM Get timestamp for backup
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "timestamp=%dt:~0,8%_%dt:~8,6%"

echo [BACKUP] Creating configuration backup...

REM Create backup of critical files
set "backup_file=deployment-backups\safe_backup_%timestamp%.zip"
set "files_to_backup="

if exist ".env" set "files_to_backup=!files_to_backup! .env"
if exist ".env.production" set "files_to_backup=!files_to_backup! .env.production"
if exist "docker-compose.production.yml" set "files_to_backup=!files_to_backup! docker-compose.production.yml"
if exist "docker-compose.override.yml" set "files_to_backup=!files_to_backup! docker-compose.override.yml"

if not "!files_to_backup!"=="" (
    powershell -command "Compress-Archive -Path !files_to_backup! -DestinationPath '%backup_file%' -Force" >nul 2>&1
    if errorlevel 1 (
        echo [WARNING] Backup creation failed, continuing anyway...
    ) else (
        echo [SUCCESS] Configuration backed up to %backup_file%
    )
) else (
    echo [WARNING] No configuration files found to backup
)

echo.
echo [GIT] Checking repository status...

REM Get current commit
for /f %%i in ('git rev-parse HEAD 2^>nul') do set "current_commit=%%i"
echo [INFO] Current commit: %current_commit%

REM Get current branch
for /f %%i in ('git branch --show-current 2^>nul') do set "current_branch=%%i"
echo [INFO] Current branch: %current_branch%

echo.
echo [GIT] Fetching latest changes...
git fetch origin
if errorlevel 1 (
    echo [ERROR] Failed to fetch from origin
    pause
    exit /b 1
)

REM Check if we're behind
for /f %%i in ('git rev-list --count HEAD..origin/main 2^>nul') do set "behind_count=%%i"
if "%behind_count%"=="0" (
    echo [SUCCESS] Repository is already up to date
    goto :health_check
)

echo [INFO] Repository is %behind_count% commits behind origin/main
echo [GIT] Performing safe merge update...

REM Stash local changes if any
git diff --quiet HEAD
if errorlevel 1 (
    echo [WARNING] Local changes detected, stashing for safety...
    git stash push -m "Safe deployment stash - %date% %time%"
    set "stash_created=true"
) else (
    set "stash_created=false"
)

REM Perform merge
git merge origin/main --no-edit
if errorlevel 1 (
    echo [ERROR] Merge failed - there may be conflicts
    if "%stash_created%"=="true" (
        echo [INFO] Restoring stashed changes...
        git stash pop
    )
    pause
    exit /b 1
)

REM Get new commit
for /f %%i in ('git rev-parse HEAD 2^>nul') do set "new_commit=%%i"
echo [SUCCESS] Successfully updated to commit: %new_commit%

REM Restore stashed changes
if "%stash_created%"=="true" (
    echo [INFO] Restoring stashed changes...
    git stash pop
)

echo.
echo [VALIDATION] Checking environment...

REM Check critical files
set "validation_passed=true"

if not exist ".env" (
    echo [ERROR] Critical file .env is missing
    set "validation_passed=false"
)

if not exist "docker-compose.yml" (
    echo [ERROR] Critical file docker-compose.yml is missing
    set "validation_passed=false"
)

REM Create production compose file if missing
if not exist "docker-compose.production.yml" (
    if exist "docker-compose.production.yml.example" (
        echo [WARNING] Production compose file missing, creating from template
        copy "docker-compose.production.yml.example" "docker-compose.production.yml" >nul
        echo [SUCCESS] Created docker-compose.production.yml from template
    ) else (
        echo [ERROR] No production compose configuration available
        set "validation_passed=false"
    )
)

if "%validation_passed%"=="false" (
    echo [ERROR] Environment validation failed
    pause
    exit /b 1
)

echo [SUCCESS] Environment validation passed

echo.
echo [DOCKER] Checking if restart is needed...

REM Check if critical files changed
set "needs_restart=false"
if not "%current_commit%"=="%new_commit%" (
    echo [INFO] Code changes detected - restart required
    set "needs_restart=true"
)

if "%needs_restart%"=="true" (
    echo [DOCKER] Performing rolling restart...
    
    REM Check if app is running
    docker compose ps | findstr "gameplan-app" | findstr "Up" >nul
    if not errorlevel 1 (
        echo [INFO] Building updated images...
        docker compose build --no-cache gameplan-app
        
        echo [INFO] Performing rolling restart...
        docker compose up -d --no-deps gameplan-app
    ) else (
        echo [INFO] Application not running, starting services...
        docker compose -f docker-compose.yml -f docker-compose.production.yml up -d
    )
    
    echo [SUCCESS] Rolling restart completed
) else (
    echo [SUCCESS] No restart required - application continues running
)

:health_check
echo.
echo [HEALTH] Verifying application health...

set "max_attempts=24"
set "attempt=1"

:health_loop
if %attempt% gtr %max_attempts% (
    echo [ERROR] Health verification failed after %max_attempts% attempts
    goto :rollback
)

echo [INFO] Health check attempt %attempt%/%max_attempts%...

REM Check health endpoint
curl -s --max-time 5 "http://localhost:3000/api/health" >nul 2>&1
if not errorlevel 1 (
    echo [SUCCESS] Application is healthy and responding
    goto :success
)

timeout /t 5 /nobreak >nul
set /a attempt+=1
goto :health_loop

:rollback
echo.
echo [ROLLBACK] Health check failed, attempting rollback...

if exist "%backup_file%" (
    echo [INFO] Restoring configuration from backup...
    docker compose down >nul 2>&1
    
    powershell -command "Expand-Archive -Path '%backup_file%' -DestinationPath '.' -Force" >nul 2>&1
    
    if not "%current_commit%"=="" (
        echo [INFO] Resetting git to previous commit...
        git reset --hard %current_commit% >nul 2>&1
    )
    
    docker compose -f docker-compose.yml -f docker-compose.production.yml up -d >nul 2>&1
    echo [SUCCESS] Rollback completed
) else (
    echo [ERROR] No backup available for rollback
)

pause
exit /b 1

:success
echo.
echo ================================
echo   Deployment Completed Successfully!
echo ================================
echo.
echo Application URL: http://localhost:3000
echo Health Check: http://localhost:3000/api/health
echo.
echo Backup created: %backup_file%
echo.

REM Show container status
echo [STATUS] Current container status:
docker compose ps

echo.
echo [SUCCESS] Safe deployment update completed!
echo.
pause
