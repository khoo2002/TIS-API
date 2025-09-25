# TIS-API Database Backup & Restore Guide

This guide provides safe methods to backup and restore your TIS-API database, avoiding the corruption issues that can occur with direct volume copying.

## Quick Start (Windows)

### Create a Backup
```powershell
# Simple backup (creates compressed files)
.\scripts\backup_docker.ps1

# Custom backup directory  
.\scripts\backup_docker.ps1 -BackupDir "C:\MyBackups"
```

### Restore from Backup
```powershell
# Restore with confirmation prompt
.\scripts\restore_docker.ps1 -BackupFile ".\backups\tis_api_complete_20250925_143022.sql.zip"

# Restore without confirmation (be careful!)
.\scripts\restore_docker.ps1 -BackupFile ".\backups\tis_api_complete_20250925_143022.sql.zip" -Force
```

## Understanding the Problem

Your original backup `tis-api_postgres_data.tar.gz` contains corrupted PostgreSQL WAL (Write-Ahead Log) files, which is why direct volume restoration fails with:

```
PANIC: could not locate a valid checkpoint record
```

## Safe Backup Methods

### 1. Docker-based SQL Dumps (Recommended)

**Advantages:**
- ✅ Platform independent  
- ✅ Human readable
- ✅ Avoids WAL corruption
- ✅ Can be restored to different PostgreSQL versions
- ✅ Includes data validation

**Windows:**
```powershell
.\scripts\backup_docker.ps1
```

**Linux/macOS:**
```bash
./scripts/backup_docker.sh
```

### 2. Application-level Python Backups

For more control over the backup process:

```bash
# Set environment variables
export DATABASE_URL=postgresql://cveuser:cvepass@localhost:5432/cvedb
export BACKUP_DIR=./backups

# Run backup
python scripts/backup_database.py
```

### 3. Live Database Dumps (while containers running)

```bash
# Schema only
docker exec postgres pg_dump -U cveuser -d cvedb --schema-only > schema.sql

# Data only  
docker exec postgres pg_dump -U cveuser -d cvedb --data-only --column-inserts > data.sql

# Complete dump
docker exec postgres pg_dump -U cveuser -d cvedb > complete_backup.sql
```

## Backup File Types

### Schema Files (`*_schema_*.sql`)
- Database structure only (tables, indexes, views)
- Fast to restore
- Use for setting up new environments

### Data Files (`*_backup_*.sql`) 
- Data only (without structure)
- Requires existing schema
- Use for data migration

### Combined Files (`*_complete_*.sql`)
- Everything in one file
- **Recommended for full restores**
- Self-contained and portable

### Metadata Files (`*.json`)
- Backup statistics and information
- Helps verify backup integrity

## Restore Process

### 1. Stop API Services
```bash
docker compose stop api ingest-worker
```

### 2. Restore Database
```powershell
# Windows
.\scripts\restore_docker.ps1 -BackupFile "path\to\backup.sql.zip"

# Linux/macOS  
./scripts/restore_docker.sh path/to/backup.sql
```

### 3. Start Services
```bash
docker compose up -d api ingest-worker
```

### 4. Verify Restore
```bash
# Check API health
curl http://localhost:8000/health

# Check database stats
curl http://localhost:8000/stats
```

## Recovering from Your Current Situation

Since your existing backup is corrupted, here's what to do:

### Option 1: Start Fresh (Recommended)
1. Start with a clean database
2. Let the ingest process rebuild your data from sources
3. Set up regular backups going forward

```bash
# Remove corrupted volume
docker volume rm tis-api_postgres_data

# Start fresh
docker compose up -d api ingest-worker

# The system will rebuild from NVD/CISA APIs
```

### Option 2: Try Data Recovery (Advanced)
If you have critical custom data (curations, alerts), you could try:

1. Extract specific tables from the corrupted backup
2. Use PostgreSQL recovery tools
3. Manual data extraction from the tar.gz file

This requires PostgreSQL expertise and is not guaranteed to work.

## Best Practices

### Automated Backups

Add to your `docker-compose.yml`:

```yaml
services:
  backup:
    image: postgres:15-alpine
    environment:
      - PGPASSWORD=cvepass
    volumes:
      - ./backups:/backups
      - ./scripts:/scripts
    command: |
      sh -c "
        while true; do
          sleep 3600  # Wait 1 hour
          /scripts/backup_docker.sh
        done
      "
    depends_on:
      - postgres
```

### Backup Schedule
- **Daily**: Automated backups during low-traffic hours
- **Before updates**: Manual backup before system changes
- **Weekly**: Test restore procedures
- **Monthly**: Archive old backups, verify integrity

### Storage Recommendations
- Keep multiple backup generations (daily for 7 days, weekly for 4 weeks)
- Store backups outside the docker host
- Consider cloud storage for critical data
- Compress backups to save space

### Monitoring
```bash
# Check backup file sizes
ls -lh ./backups/

# Verify recent backups exist
find ./backups -name "*.sql*" -mtime -1

# Test backup integrity
gzip -t ./backups/*.gz 2>/dev/null && echo "Compressed files OK"
```

## Troubleshooting

### "Container not found"
```bash
# Check running containers
docker ps

# Use correct container name
docker compose ps
```

### "Permission denied"
```bash
# Make scripts executable (Linux/macOS)
chmod +x scripts/*.sh

# Or run with bash
bash scripts/backup_docker.sh
```

### "Database connection failed"
```bash
# Check if PostgreSQL is running
docker compose logs postgres

# Verify database credentials in .env file
```

### Large backup files
```bash
# Use compression
gzip large_backup.sql

# Or use pg_dump with compression
docker exec postgres pg_dump -U cveuser -d cvedb -Fc > backup.dump
```

## Recovery Testing

Regularly test your backup/restore process:

```bash
# 1. Create test environment
docker compose -f docker-compose.test.yml up -d

# 2. Restore backup to test environment
./scripts/restore_docker.sh backup.sql

# 3. Verify data integrity
curl http://localhost:8001/stats  # assuming different port

# 4. Cleanup test environment
docker compose -f docker-compose.test.yml down -v
```

## Support

If you encounter issues:

1. Check the logs: `docker compose logs`
2. Verify disk space: `df -h`
3. Test database connectivity: `docker exec postgres psql -U cveuser -d cvedb -c "SELECT 1"`
4. Review backup metadata files for clues

The new backup system is designed to be reliable and avoid the volume corruption issues you experienced.