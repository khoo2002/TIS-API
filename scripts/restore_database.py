#!/usr/bin/env python3
"""
Safe database restore script for TIS-API
Restores data from SQL backup files with proper validation.
"""
import asyncio
import asyncpg
import json
import os
import sys
from datetime import datetime
from pathlib import Path

# Database connection settings
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://cveuser:cvepass@localhost:5432/cvedb')

async def restore_backup(backup_file, metadata_file=None):
    """Restore database from backup file"""
    
    backup_path = Path(backup_file)
    if not backup_path.exists():
        print(f"Error: Backup file {backup_file} not found")
        sys.exit(1)
    
    print(f"Restoring from: {backup_file}")
    
    # Load and display metadata if available
    if metadata_file and Path(metadata_file).exists():
        try:
            with open(metadata_file) as f:
                metadata = json.load(f)
            print("Backup metadata:")
            print(f"  Created: {metadata.get('backup_timestamp', 'Unknown')}")
            print(f"  Tables: {metadata.get('table_counts', {})}")
            print()
        except Exception as e:
            print(f"Warning: Could not read metadata: {e}")
    
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        
        # Verify database structure exists
        print("Verifying database structure...")
        await verify_database_structure(conn)
        
        # Read and execute backup file
        print("Executing restore...")
        with open(backup_file, 'r', encoding='utf-8') as f:
            sql_content = f.read()
        
        # Execute the backup SQL (it should be wrapped in a transaction)
        await conn.execute(sql_content)
        
        # Verify restore
        print("Verifying restore...")
        await verify_restore(conn)
        
        await conn.close()
        
        print("Restore completed successfully!")
        print("\nNext steps:")
        print("1. Start your TIS-API services")
        print("2. The materialized views will be refreshed automatically")
        print("3. Check the /stats endpoint to verify data integrity")
        
    except Exception as e:
        print(f"Restore failed: {e}")
        sys.exit(1)

async def verify_database_structure(conn):
    """Verify that required tables and structure exist"""
    
    required_tables = ['nvd_cves', 'cisa_kev', 'ingest_state', 'refresh_state']
    
    for table in required_tables:
        exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = $1
            )
        """, table)
        
        if not exists:
            print(f"Error: Required table '{table}' does not exist")
            print("Please ensure the database schema is properly initialized")
            sys.exit(1)
    
    print("✓ Database structure verified")

async def verify_restore(conn):
    """Verify that the restore was successful"""
    
    # Check main tables have data
    tables_to_check = {
        'nvd_cves': 'CVE records',
        'cisa_kev': 'CISA KEV records', 
        'ingest_state': 'Ingest state',
    }
    
    print("\nRestore verification:")
    for table, description in tables_to_check.items():
        try:
            count = await conn.fetchval(f'SELECT COUNT(*) FROM "{table}"')
            print(f"  ✓ {description}: {count:,} records")
        except Exception as e:
            print(f"  ⚠ {description}: Error checking - {e}")
    
    # Check materialized views exist (they may be empty until refreshed)
    views = ['cve_overview']
    for view in views:
        exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM pg_matviews 
                WHERE schemaname = 'public' AND matviewname = $1
            )
        """, view)
        
        if exists:
            print(f"  ✓ Materialized view '{view}' exists")
        else:
            print(f"  ⚠ Materialized view '{view}' missing")

def main():
    if len(sys.argv) < 2:
        print("Usage: python restore_database.py <backup_file> [metadata_file]")
        print("\nExample:")
        print("  python restore_database.py ./backups/tis_api_backup_20250925_143022.sql")
        sys.exit(1)
    
    backup_file = sys.argv[1]
    metadata_file = sys.argv[2] if len(sys.argv) > 2 else None
    
    # Infer metadata file if not provided
    if not metadata_file:
        backup_path = Path(backup_file)
        metadata_path = backup_path.with_suffix('.json')
        if metadata_path.exists():
            metadata_file = str(metadata_path)
    
    asyncio.run(restore_backup(backup_file, metadata_file))

if __name__ == "__main__":
    main()