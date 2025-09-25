# PowerShell script for restoring TIS-API database on Windows

param(
    [Parameter(Mandatory=$true)]
    [string]$BackupFile,
    
    [switch]$Force,
    
    [string]$ContainerName = "postgres",
    [string]$DbName = "cvedb", 
    [string]$DbUser = "cveuser"
)

Write-Host "TIS-API Database Restore Script (Windows)" -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green

# Check if backup file exists
if (!(Test-Path $BackupFile)) {
    Write-Host "Error: Backup file '$BackupFile' not found" -ForegroundColor Red
    exit 1
}

Write-Host "Restore file: $BackupFile" -ForegroundColor Yellow

# Handle compressed files
$tempFile = $null
if ($BackupFile -match "\.zip$") {
    Write-Host "Extracting compressed backup..." -ForegroundColor Yellow
    $tempDir = "$env:TEMP/tis_restore_$(Get-Date -Format 'yyyyMMddHHmmss')"
    Expand-Archive -Path $BackupFile -DestinationPath $tempDir -Force
    
    # Find the SQL file in the extracted directory
    $sqlFile = Get-ChildItem -Path $tempDir -Filter "*.sql" | Select-Object -First 1
    if ($sqlFile) {
        $tempFile = $sqlFile.FullName
        $BackupFile = $tempFile
    } else {
        Write-Host "Error: No SQL file found in the archive" -ForegroundColor Red
        exit 1
    }
}

# Show current database status
Write-Host "`nCurrent database status:" -ForegroundColor Yellow
try {
    docker exec $ContainerName psql -U $DbUser -d $DbName -c "SELECT 'nvd_cves' as table_name, COUNT(*) as record_count FROM nvd_cves UNION ALL SELECT 'cisa_kev' as table_name, COUNT(*) as record_count FROM cisa_kev UNION ALL SELECT 'cve_curations' as table_name, COUNT(*) as record_count FROM cve_curations UNION ALL SELECT 'alerts' as table_name, COUNT(*) as record_count FROM alerts;"
} catch {
    Write-Host "Could not query database (may be empty or not initialized)" -ForegroundColor Gray
}

Write-Host ""

# Confirmation unless -Force
if (!$Force) {
    Write-Host "WARNING: This will replace ALL data in the database!" -ForegroundColor Red
    Write-Host "Container: $ContainerName" -ForegroundColor Yellow
    Write-Host "Database: $DbName" -ForegroundColor Yellow
    Write-Host ""
    
    $response = Read-Host "Are you sure you want to continue? (yes/no)"
    if ($response -notmatch "^[Yy][Ee][Ss]$") {
        Write-Host "Restore cancelled" -ForegroundColor Yellow
        exit 0
    }
}

Write-Host "`nStarting restore..." -ForegroundColor Green

try {
    # Stop API services
    Write-Host "Stopping API services..." -ForegroundColor Yellow
    docker compose stop api ingest-worker 2>$null
    
    # Restore database
    Write-Host "Restoring database from: $BackupFile" -ForegroundColor Yellow
    
    # Use Get-Content and pipe to docker exec for better Windows compatibility
    Get-Content $BackupFile -Raw | docker exec -i $ContainerName psql -U $DbUser -d $DbName
    
    if ($LASTEXITCODE -eq 0) {
        Write-Host "✓ Database restored successfully" -ForegroundColor Green
    } else {
        Write-Host "✗ Database restore failed" -ForegroundColor Red
        exit 1
    }
    
    # Cleanup temp files
    if ($tempFile -and (Test-Path $tempFile)) {
        Remove-Item (Split-Path $tempFile -Parent) -Recurse -Force
        Write-Host "Cleaned up temporary files" -ForegroundColor Gray
    }
    
    # Verify restore
    Write-Host "`nVerifying restore..." -ForegroundColor Yellow
    docker exec $ContainerName psql -U $DbUser -d $DbName -c "SELECT 'nvd_cves' as table_name, COUNT(*) as record_count FROM nvd_cves UNION ALL SELECT 'cisa_kev' as table_name, COUNT(*) as record_count FROM cisa_kev UNION ALL SELECT 'cve_curations' as table_name, COUNT(*) as record_count FROM cve_curations UNION ALL SELECT 'alerts' as table_name, COUNT(*) as record_count FROM alerts;"
    
    Write-Host "`n✓ Restore completed successfully!" -ForegroundColor Green
    Write-Host "`nNext steps:" -ForegroundColor Cyan
    Write-Host "1. Start your services: docker compose up -d api ingest-worker"
    Write-Host "2. Check the API health: curl http://localhost:8000/health" 
    Write-Host "3. Verify data integrity: curl http://localhost:8000/stats"

} catch {
    Write-Host "Error during restore: $_" -ForegroundColor Red
    
    # Cleanup on error
    if ($tempFile -and (Test-Path $tempFile)) {
        Remove-Item (Split-Path $tempFile -Parent) -Recurse -Force
    }
    
    exit 1
}