#!/usr/bin/env bash
# Docker-based backup script for TIS-API
# This script runs the backup inside the Docker environment

set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-./backups}"
CONTAINER_NAME="${CONTAINER_NAME:-postgres}"
DB_NAME="${POSTGRES_DB:-cvedb}"
DB_USER="${POSTGRES_USER:-cveuser}"

echo "TIS-API Database Backup Script"
echo "=============================="

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Generate timestamp
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/tis_api_backup_$TIMESTAMP.sql"
SCHEMA_FILE="$BACKUP_DIR/tis_api_schema_$TIMESTAMP.sql"

echo "Creating backup files:"
echo "  Data: $BACKUP_FILE"
echo "  Schema: $SCHEMA_FILE"

# Export schema only (structure)
echo "Exporting database schema..."
docker exec "$CONTAINER_NAME" pg_dump \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  --schema-only \
  --no-owner \
  --no-privileges > "$SCHEMA_FILE"

# Export data only (without schema)
echo "Exporting database data..."
docker exec "$CONTAINER_NAME" pg_dump \
  -U "$DB_USER" \
  -d "$DB_NAME" \
  --data-only \
  --no-owner \
  --no-privileges \
  --column-inserts > "$BACKUP_FILE"

# Create a combined backup for easy restore
COMBINED_FILE="$BACKUP_DIR/tis_api_complete_$TIMESTAMP.sql"
echo "Creating combined backup: $COMBINED_FILE"

cat > "$COMBINED_FILE" << EOF
-- TIS-API Complete Database Backup
-- Created: $(date -Iseconds)
-- 
-- This file contains both schema and data
-- To restore: psql -U username -d database_name -f this_file.sql

BEGIN;

-- Disable triggers for faster import
SET session_replication_role = replica;

EOF

# Append schema (without the final commit/transaction commands)
sed '/^BEGIN;/d; /^COMMIT;/d' "$SCHEMA_FILE" >> "$COMBINED_FILE"

cat >> "$COMBINED_FILE" << EOF

-- Now insert data
EOF

# Append data
sed '/^BEGIN;/d; /^COMMIT;/d' "$BACKUP_FILE" >> "$COMBINED_FILE"

cat >> "$COMBINED_FILE" << EOF

-- Re-enable triggers
SET session_replication_role = DEFAULT;

-- Refresh materialized views
REFRESH MATERIALIZED VIEW IF EXISTS cve_overview;
REFRESH MATERIALIZED VIEW IF EXISTS cve_public_overview;
REFRESH MATERIALIZED VIEW IF EXISTS alerts_public;

COMMIT;

-- Backup completed successfully
EOF

# Create metadata
METADATA_FILE="$BACKUP_DIR/tis_api_backup_$TIMESTAMP.json"
echo "Creating metadata: $METADATA_FILE"

# Get statistics from database
STATS=$(docker exec "$CONTAINER_NAME" psql -U "$DB_USER" -d "$DB_NAME" -t -c "
SELECT json_build_object(
  'nvd_cves', COALESCE((SELECT COUNT(*) FROM nvd_cves), 0),
  'cisa_kev', COALESCE((SELECT COUNT(*) FROM cisa_kev), 0),
  'cve_curations', COALESCE((SELECT COUNT(*) FROM cve_curations), 0),
  'alerts', COALESCE((SELECT COUNT(*) FROM alerts), 0)
);")

cat > "$METADATA_FILE" << EOF
{
  "backup_timestamp": "$(date -Iseconds)",
  "backup_type": "complete",
  "files": {
    "schema": "$(basename "$SCHEMA_FILE")",
    "data": "$(basename "$BACKUP_FILE")", 
    "combined": "$(basename "$COMBINED_FILE")"
  },
  "table_counts": $STATS,
  "backup_version": "1.0"
}
EOF

# Compress backups to save space
echo "Compressing backups..."
gzip "$BACKUP_FILE" "$SCHEMA_FILE" "$COMBINED_FILE"

echo ""
echo "Backup completed successfully!"
echo "Files created:"
echo "  Schema: ${SCHEMA_FILE}.gz"
echo "  Data: ${BACKUP_FILE}.gz" 
echo "  Combined: ${COMBINED_FILE}.gz"
echo "  Metadata: $METADATA_FILE"
echo ""
echo "To restore from combined backup:"
echo "  gunzip ${COMBINED_FILE}.gz"
echo "  docker exec -i $CONTAINER_NAME psql -U $DB_USER -d $DB_NAME < $COMBINED_FILE"