#!/usr/bin/env bash
# Docker-based restore script for TIS-API

set -e

# Check arguments
if [ $# -lt 1 ]; then
    echo "Usage: $0 <backup_file> [--force]"
    echo ""
    echo "Examples:"
    echo "  $0 ./backups/tis_api_complete_20250925_143022.sql"
    echo "  $0 ./backups/tis_api_complete_20250925_143022.sql.gz --force"
    echo ""
    echo "Options:"
    echo "  --force    Skip confirmation prompt"
    exit 1
fi

BACKUP_FILE="$1"
FORCE="$2"

# Configuration
CONTAINER_NAME="${CONTAINER_NAME:-postgres}"
DB_NAME="${POSTGRES_DB:-cvedb}"
DB_USER="${POSTGRES_USER:-cveuser}"

echo "TIS-API Database Restore Script"
echo "==============================="

# Check if backup file exists
if [[ ! -f "$BACKUP_FILE" ]]; then
    echo "Error: Backup file '$BACKUP_FILE' not found"
    exit 1
fi

echo "Restore file: $BACKUP_FILE"

# Check if file is compressed
TEMP_FILE=""
if [[ "$BACKUP_FILE" == *.gz ]]; then
    echo "Decompressing backup file..."
    TEMP_FILE="${BACKUP_FILE%.gz}"
    gunzip -c "$BACKUP_FILE" > "$TEMP_FILE"
    BACKUP_FILE="$TEMP_FILE"
fi

# Show current database stats
echo ""
echo "Current database status:"
docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -c "
SELECT 
  'nvd_cves' as table_name, COUNT(*) as record_count FROM nvd_cves
UNION ALL
SELECT 
  'cisa_kev' as table_name, COUNT(*) as record_count FROM cisa_kev  
UNION ALL
SELECT 
  'cve_curations' as table_name, COUNT(*) as record_count FROM cve_curations
UNION ALL
SELECT 
  'alerts' as table_name, COUNT(*) as record_count FROM alerts;
" 2>/dev/null || echo "Could not query database (may be empty or not initialized)"

echo ""

# Confirmation unless --force
if [[ "$FORCE" != "--force" ]]; then
    echo "WARNING: This will replace ALL data in the database!"
    echo "Container: $CONTAINER_NAME"
    echo "Database: $DB_NAME"
    echo ""
    read -p "Are you sure you want to continue? (yes/no): " -r
    if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
        echo "Restore cancelled"
        exit 0
    fi
fi

echo ""
echo "Starting restore..."

# Stop API services to prevent conflicts during restore
echo "Stopping API services..."
docker compose stop api ingest-worker 2>/dev/null || true

# Restore database
echo "Restoring database from: $BACKUP_FILE"
docker exec -i "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" < "$BACKUP_FILE"

if [ $? -eq 0 ]; then
    echo "✓ Database restored successfully"
else
    echo "✗ Database restore failed"
    exit 1
fi

# Cleanup temp file
if [[ -n "$TEMP_FILE" && -f "$TEMP_FILE" ]]; then
    rm "$TEMP_FILE"
    echo "Cleaned up temporary file"
fi

# Verify restore
echo ""
echo "Verifying restore..."
docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -c "
SELECT 
  'nvd_cves' as table_name, COUNT(*) as record_count FROM nvd_cves
UNION ALL
SELECT 
  'cisa_kev' as table_name, COUNT(*) as record_count FROM cisa_kev
UNION ALL  
SELECT 
  'cve_curations' as table_name, COUNT(*) as record_count FROM cve_curations
UNION ALL
SELECT 
  'alerts' as table_name, COUNT(*) as record_count FROM alerts;
"

echo ""
echo "✓ Restore completed successfully!"
echo ""
echo "Next steps:"
echo "1. Start your services: docker compose up -d api ingest-worker"
echo "2. Check the API health: curl http://localhost:8000/health"
echo "3. Verify data integrity: curl http://localhost:8000/stats"