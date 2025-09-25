# PowerShell script for backing up TIS-API database on Windows
# This script uses Docker to create safe backups

param(
    [string]$BackupDir = "./backups",
    [string]$ContainerName = "postgres", 
    [string]$DbName = "cvedb",
    [string]$DbUser = "cveuser"
)

Write-Host "TIS-API Database Backup Script (Windows)" -ForegroundColor Green
Write-Host "=========================================" -ForegroundColor Green

# Create backup directory
if (!(Test-Path $BackupDir)) {
    New-Item -ItemType Directory -Path $BackupDir -Force | Out-Null
}

# Generate timestamp
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$backupFile = "$BackupDir/tis_api_backup_$timestamp.sql"
$schemaFile = "$BackupDir/tis_api_schema_$timestamp.sql"  
$combinedFile = "$BackupDir/tis_api_complete_$timestamp.sql"
$metadataFile = "$BackupDir/tis_api_backup_$timestamp.json"

Write-Host "Creating backup files:" -ForegroundColor Yellow
Write-Host "  Schema: $schemaFile"
Write-Host "  Data: $backupFile"
Write-Host "  Combined: $combinedFile"
Write-Host "  Metadata: $metadataFile"

try {
    # Export schema
    Write-Host "`nExporting database schema..." -ForegroundColor Yellow
    docker exec $ContainerName pg_dump -U $DbUser -d $DbName --schema-only --no-owner --no-privileges | Out-File -FilePath $schemaFile -Encoding UTF8

    # Export data
    Write-Host "Exporting database data..." -ForegroundColor Yellow  
    docker exec $ContainerName pg_dump -U $DbUser -d $DbName --data-only --no-owner --no-privileges --column-inserts | Out-File -FilePath $backupFile -Encoding UTF8

    # Create combined backup
    Write-Host "Creating combined backup..." -ForegroundColor Yellow
    
    $combinedContent = @"
-- TIS-API Complete Database Backup
-- Created: $(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ")
-- 
-- This file contains both schema and data
-- To restore: docker exec -i postgres psql -U cveuser -d cvedb < this_file.sql

BEGIN;

-- Disable triggers for faster import
SET session_replication_role = replica;

"@

    # Add schema (without BEGIN/COMMIT)
    $schemaContent = Get-Content $schemaFile | Where-Object { $_ -notmatch "^(BEGIN|COMMIT);" }
    $combinedContent += "`n" + ($schemaContent -join "`n")
    
    $combinedContent += "`n`n-- Now insert data`n"
    
    # Add data (without BEGIN/COMMIT)
    $dataContent = Get-Content $backupFile | Where-Object { $_ -notmatch "^(BEGIN|COMMIT);" }
    $combinedContent += ($dataContent -join "`n")
    
    $combinedContent += @"

-- Re-enable triggers
SET session_replication_role = DEFAULT;

-- Refresh materialized views
REFRESH MATERIALIZED VIEW IF EXISTS cve_overview;
REFRESH MATERIALIZED VIEW IF EXISTS cve_public_overview; 
REFRESH MATERIALIZED VIEW IF EXISTS alerts_public;

COMMIT;

-- Backup completed successfully
"@

    $combinedContent | Out-File -FilePath $combinedFile -Encoding UTF8

    # Create metadata
    Write-Host "Creating metadata..." -ForegroundColor Yellow
    
    # Get database statistics
    $statsJson = docker exec $ContainerName psql -U $DbUser -d $DbName -t -c "SELECT json_build_object('nvd_cves', COALESCE((SELECT COUNT(*) FROM nvd_cves), 0), 'cisa_kev', COALESCE((SELECT COUNT(*) FROM cisa_kev), 0), 'cve_curations', COALESCE((SELECT COUNT(*) FROM cve_curations), 0), 'alerts', COALESCE((SELECT COUNT(*) FROM alerts), 0));"
    
    $metadata = @{
        backup_timestamp = Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ"
        backup_type = "complete"
        files = @{
            schema = Split-Path $schemaFile -Leaf
            data = Split-Path $backupFile -Leaf
            combined = Split-Path $combinedFile -Leaf
        }
        table_counts = $statsJson | ConvertFrom-Json
        backup_version = "1.0"
    }
    
    $metadata | ConvertTo-Json -Depth 3 | Out-File -FilePath $metadataFile -Encoding UTF8

    # Compress files to save space
    Write-Host "Compressing backups..." -ForegroundColor Yellow
    
    Compress-Archive -Path $backupFile -DestinationPath "$backupFile.zip" -Force
    Compress-Archive -Path $schemaFile -DestinationPath "$schemaFile.zip" -Force  
    Compress-Archive -Path $combinedFile -DestinationPath "$combinedFile.zip" -Force
    
    # Remove uncompressed files
    Remove-Item $backupFile, $schemaFile, $combinedFile

    Write-Host "`nBackup completed successfully!" -ForegroundColor Green
    Write-Host "Files created:" -ForegroundColor Yellow
    Write-Host "  Schema: $schemaFile.zip"
    Write-Host "  Data: $backupFile.zip"
    Write-Host "  Combined: $combinedFile.zip" 
    Write-Host "  Metadata: $metadataFile"
    Write-Host "`nTo restore from combined backup:" -ForegroundColor Cyan
    Write-Host "  Expand-Archive '$combinedFile.zip' -DestinationPath './temp'"
    Write-Host "  docker exec -i postgres psql -U cveuser -d cvedb < ./temp/$(Split-Path $combinedFile -Leaf)"

} catch {
    Write-Host "Error during backup: $_" -ForegroundColor Red
    exit 1
}