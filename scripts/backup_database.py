#!/usr/bin/env python3
"""
Safe database backup script for TIS-API
Creates SQL dumps of all data tables with proper ordering for restore.
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
BACKUP_DIR = os.getenv('BACKUP_DIR', './backups')

async def create_backup():
    """Create a complete backup of TIS-API database"""
    
    # Create backup directory
    backup_dir = Path(BACKUP_DIR)
    backup_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_file = backup_dir / f"tis_api_backup_{timestamp}.sql"
    
    print(f"Creating backup: {backup_file}")
    
    try:
        conn = await asyncpg.connect(DATABASE_URL)
        
        with open(backup_file, 'w', encoding='utf-8') as f:
            f.write("-- TIS-API Database Backup\n")
            f.write(f"-- Created: {datetime.now().isoformat()}\n")
            f.write("-- WARNING: This file contains sensitive data\n\n")
            
            f.write("BEGIN;\n\n")
            
            # 1. Export core data tables in dependency order
            tables_to_export = [
                'nvd_cves',
                'cisa_kev', 
                'ingest_state',
                'refresh_state',
                'crawl_runs',
                'crawl_run_verifications',
                'cve_curations',
                'cve_curation_versions',
                'alerts',
                'user_profiles'
            ]
            
            for table in tables_to_export:
                print(f"Exporting table: {table}")
                await export_table_data(conn, f, table)
            
            f.write("\nCOMMIT;\n")
            f.write("\n-- Refresh materialized views after restore\n")
            f.write("REFRESH MATERIALIZED VIEW CONCURRENTLY cve_overview;\n")
            f.write("REFRESH MATERIALIZED VIEW cve_public_overview;\n")
            f.write("REFRESH MATERIALIZED VIEW alerts_public;\n")
        
        # Create metadata file
        metadata_file = backup_dir / f"tis_api_backup_{timestamp}.json"
        await create_backup_metadata(conn, metadata_file)
        
        await conn.close()
        
        print(f"Backup completed successfully:")
        print(f"  Data: {backup_file}")
        print(f"  Metadata: {metadata_file}")
        return backup_file, metadata_file
        
    except Exception as e:
        print(f"Backup failed: {e}")
        sys.exit(1)

async def export_table_data(conn, file_handle, table_name):
    """Export table data as INSERT statements"""
    try:
        # Check if table exists
        exists = await conn.fetchval("""
            SELECT EXISTS (
                SELECT 1 FROM information_schema.tables 
                WHERE table_schema = 'public' AND table_name = $1
            )
        """, table_name)
        
        if not exists:
            file_handle.write(f"-- Table {table_name} does not exist, skipping\n\n")
            return
        
        # Get column names
        columns = await conn.fetch("""
            SELECT column_name, data_type 
            FROM information_schema.columns 
            WHERE table_schema = 'public' AND table_name = $1
            ORDER BY ordinal_position
        """, table_name)
        
        if not columns:
            file_handle.write(f"-- Table {table_name} has no columns, skipping\n\n")
            return
            
        column_names = [col['column_name'] for col in columns]
        column_list = ', '.join(f'"{col}"' for col in column_names)
        
        # Count rows
        row_count = await conn.fetchval(f'SELECT COUNT(*) FROM "{table_name}"')
        
        file_handle.write(f"-- Exporting {table_name} ({row_count} rows)\n")
        
        if row_count == 0:
            file_handle.write(f"-- Table {table_name} is empty\n\n")
            return
        
        # Disable triggers during insert for faster restore
        file_handle.write(f"ALTER TABLE \"{table_name}\" DISABLE TRIGGER ALL;\n")
        
        # Export data in batches
        batch_size = 1000
        offset = 0
        
        while offset < row_count:
            rows = await conn.fetch(f"""
                SELECT {column_list} FROM "{table_name}" 
                ORDER BY {column_names[0]}  -- Use first column for consistent ordering
                LIMIT $1 OFFSET $2
            """, batch_size, offset)
            
            if rows:
                file_handle.write(f"INSERT INTO \"{table_name}\" ({column_list}) VALUES\n")
                
                for i, row in enumerate(rows):
                    values = []
                    for j, col in enumerate(column_names):
                        value = row[j]
                        if value is None:
                            values.append('NULL')
                        elif isinstance(value, str):
                            # Escape single quotes and wrap in quotes
                            escaped = value.replace("'", "''")
                            values.append(f"'{escaped}'")
                        elif isinstance(value, (dict, list)):
                            # JSONB columns
                            json_str = json.dumps(value).replace("'", "''")
                            values.append(f"'{json_str}'")
                        elif isinstance(value, bool):
                            values.append('TRUE' if value else 'FALSE')
                        else:
                            values.append(str(value))
                    
                    row_values = f"({', '.join(values)})"
                    if i < len(rows) - 1:
                        file_handle.write(f"  {row_values},\n")
                    else:
                        file_handle.write(f"  {row_values}\n")
                
                file_handle.write("ON CONFLICT DO NOTHING;\n")
            
            offset += batch_size
        
        # Re-enable triggers
        file_handle.write(f"ALTER TABLE \"{table_name}\" ENABLE TRIGGER ALL;\n\n")
        
    except Exception as e:
        print(f"Error exporting table {table_name}: {e}")
        file_handle.write(f"-- ERROR exporting {table_name}: {e}\n\n")

async def create_backup_metadata(conn, metadata_file):
    """Create metadata file with backup information"""
    try:
        # Get database statistics
        stats = {}
        
        tables = ['nvd_cves', 'cisa_kev', 'cve_curations', 'alerts']
        for table in tables:
            try:
                count = await conn.fetchval(f'SELECT COUNT(*) FROM "{table}"')
                stats[table] = count
            except:
                stats[table] = 0
        
        # Get latest ingest information
        ingest_info = await conn.fetch("SELECT * FROM ingest_state ORDER BY last_run DESC")
        
        metadata = {
            'backup_timestamp': datetime.now().isoformat(),
            'database_url': DATABASE_URL.replace(DATABASE_URL.split('@')[0].split('//')[1], '***'),  # Hide credentials
            'table_counts': stats,
            'ingest_state': [dict(row) for row in ingest_info] if ingest_info else [],
            'backup_version': '1.0'
        }
        
        with open(metadata_file, 'w') as f:
            json.dump(metadata, f, indent=2, default=str)
            
    except Exception as e:
        print(f"Warning: Could not create metadata file: {e}")

if __name__ == "__main__":
    asyncio.run(create_backup())