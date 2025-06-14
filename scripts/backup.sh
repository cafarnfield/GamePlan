#!/bin/bash

# GamePlan MongoDB Backup Script
# This script creates a backup of the GamePlan MongoDB database

set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-./backups}"
CONTAINER_NAME="${CONTAINER_NAME:-gameplan-mongodb}"
DATABASE_NAME="${DATABASE_NAME:-gameplan}"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="gameplan_backup_${TIMESTAMP}.archive"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}GamePlan Database Backup Script${NC}"
echo "=================================="

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo -e "${RED}Error: Docker is not running${NC}"
    exit 1
fi

# Check if container exists and is running
if ! docker ps | grep -q "$CONTAINER_NAME"; then
    echo -e "${RED}Error: Container $CONTAINER_NAME is not running${NC}"
    exit 1
fi

# Create backup directory if it doesn't exist
mkdir -p "$BACKUP_DIR"

echo -e "${YELLOW}Creating backup...${NC}"
echo "Container: $CONTAINER_NAME"
echo "Database: $DATABASE_NAME"
echo "Backup file: $BACKUP_FILE"
echo ""

# Create the backup using mongodump
docker exec "$CONTAINER_NAME" mongodump \
    --db "$DATABASE_NAME" \
    --archive="/tmp/$BACKUP_FILE" \
    --gzip

# Copy the backup file from container to host
docker cp "$CONTAINER_NAME:/tmp/$BACKUP_FILE" "$BACKUP_DIR/$BACKUP_FILE"

# Remove the backup file from container
docker exec "$CONTAINER_NAME" rm "/tmp/$BACKUP_FILE"

# Get file size
BACKUP_SIZE=$(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)

echo -e "${GREEN}Backup completed successfully!${NC}"
echo "Backup location: $BACKUP_DIR/$BACKUP_FILE"
echo "Backup size: $BACKUP_SIZE"
echo ""

# Optional: Clean up old backups (keep last 7 days)
if [ "${CLEANUP_OLD_BACKUPS:-true}" = "true" ]; then
    echo -e "${YELLOW}Cleaning up old backups (keeping last 7 days)...${NC}"
    find "$BACKUP_DIR" -name "gameplan_backup_*.archive" -type f -mtime +7 -delete
    echo "Old backups cleaned up"
fi

echo -e "${GREEN}Backup process completed!${NC}"
