#!/bin/bash

# GamePlan MongoDB Restore Script
# This script restores a backup of the GamePlan MongoDB database

set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-./backups}"
CONTAINER_NAME="${CONTAINER_NAME:-gameplan-mongodb}"
DATABASE_NAME="${DATABASE_NAME:-gameplan}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${GREEN}GamePlan Database Restore Script${NC}"
echo "=================================="

# Check if backup file is provided
if [ $# -eq 0 ]; then
    echo -e "${YELLOW}Available backup files:${NC}"
    if [ -d "$BACKUP_DIR" ]; then
        ls -la "$BACKUP_DIR"/gameplan_backup_*.archive 2>/dev/null || echo "No backup files found in $BACKUP_DIR"
    else
        echo "Backup directory $BACKUP_DIR does not exist"
    fi
    echo ""
    echo -e "${BLUE}Usage: $0 <backup_file>${NC}"
    echo "Example: $0 gameplan_backup_20231214_120000.archive"
    exit 1
fi

BACKUP_FILE="$1"

# Check if backup file exists
if [ ! -f "$BACKUP_DIR/$BACKUP_FILE" ]; then
    echo -e "${RED}Error: Backup file $BACKUP_DIR/$BACKUP_FILE not found${NC}"
    exit 1
fi

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

echo -e "${YELLOW}Restore Details:${NC}"
echo "Container: $CONTAINER_NAME"
echo "Database: $DATABASE_NAME"
echo "Backup file: $BACKUP_FILE"
echo "Backup size: $(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)"
echo ""

# Confirmation prompt
echo -e "${RED}WARNING: This will replace all data in the $DATABASE_NAME database!${NC}"
read -p "Are you sure you want to continue? (yes/no): " -r
if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Restore cancelled"
    exit 0
fi

echo -e "${YELLOW}Starting restore process...${NC}"

# Copy backup file to container
echo "Copying backup file to container..."
docker cp "$BACKUP_DIR/$BACKUP_FILE" "$CONTAINER_NAME:/tmp/$BACKUP_FILE"

# Drop existing database (optional, but recommended for clean restore)
echo "Dropping existing database..."
docker exec "$CONTAINER_NAME" mongosh --eval "db.getSiblingDB('$DATABASE_NAME').dropDatabase()"

# Restore the backup using mongorestore
echo "Restoring database from backup..."
docker exec "$CONTAINER_NAME" mongorestore \
    --archive="/tmp/$BACKUP_FILE" \
    --gzip

# Remove the backup file from container
docker exec "$CONTAINER_NAME" rm "/tmp/$BACKUP_FILE"

echo -e "${GREEN}Database restore completed successfully!${NC}"
echo ""

# Verify the restore
echo -e "${YELLOW}Verifying restore...${NC}"
COLLECTIONS=$(docker exec "$CONTAINER_NAME" mongosh --quiet --eval "db.getSiblingDB('$DATABASE_NAME').getCollectionNames().length")
echo "Collections restored: $COLLECTIONS"

if [ "$COLLECTIONS" -gt 0 ]; then
    echo -e "${GREEN}Restore verification successful!${NC}"
else
    echo -e "${RED}Warning: No collections found after restore${NC}"
fi

echo ""
echo -e "${GREEN}Restore process completed!${NC}"
echo -e "${YELLOW}Note: You may need to restart the GamePlan application container${NC}"
