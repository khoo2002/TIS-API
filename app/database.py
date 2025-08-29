"""
Simplified database module for JSONB-based CVE storage
Clean design using PostgreSQL JSONB for flexibility
"""
import asyncio
import json
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime
import os
import hashlib
import zoneinfo
import uuid

# Presentation timezone from environment; default to Asia/Kuala_Lumpur
APP_TZ = os.getenv('APP_TIMEZONE', 'Asia/Kuala_Lumpur')
try:
    TZINFO = zoneinfo.ZoneInfo(APP_TZ)
except Exception:
    TZINFO = zoneinfo.ZoneInfo('Asia/Kuala_Lumpur')

# asyncpg is an optional runtime dependency for editors/linting environments
# that may not have it installed. Import defensively and provide a clear
# runtime error if code attempts DB operations without asyncpg available.
try:
    import asyncpg
    _HAS_ASYNCPG = True
except Exception:
    asyncpg = None
    _HAS_ASYNCPG = False


def _require_asyncpg() -> None:
    if not _HAS_ASYNCPG:
        raise RuntimeError("asyncpg is required for database operations; install it with 'pip install asyncpg'")

logger = logging.getLogger(__name__)

class DatabasePool:
    """Simple database connection pool manager"""
    def __init__(self):
        self.pool = None
        # Protect concurrent initialize() calls so only one pool is created
        self._init_lock = asyncio.Lock()

    async def initialize(self):
        """Initialize the database connection pool.

        This will attempt to create an asyncpg pool using either a
        single DATABASE_URL environment variable or granular POSTGRES_*
        environment variables. It will retry with exponential backoff
        to tolerate startup race conditions.
        """
        _require_asyncpg()

        # Prefer a single DATABASE_URL if provided (works well in containers)
        database_url = os.getenv('DATABASE_URL')

        # Fallback granular settings
        db_config = {
            'host': os.getenv('POSTGRES_HOST', 'localhost'),
            'port': int(os.getenv('POSTGRES_PORT', 5432)),
            'user': os.getenv('POSTGRES_USER', 'cveuser'),
            'password': os.getenv('POSTGRES_PASSWORD', 'cvepass'),
            'database': os.getenv('POSTGRES_DB', 'cvedb'),
            'min_size': 2,
            'max_size': 10
        }

        # Retry loop with exponential backoff to handle race conditions at startup
        max_attempts = int(os.getenv('DB_INIT_MAX_ATTEMPTS', 6))
        base_delay = float(os.getenv('DB_INIT_BASE_DELAY', 1.5))

        # Ensure only one concurrent initializer runs to avoid creating multiple pools
        async with self._init_lock:
            if self.pool:
                # Another coroutine already initialized the pool while we waited
                logger.debug('Database pool already initialized by another task')
                return

            last_exc = None
            for attempt in range(1, max_attempts + 1):
                try:
                    if database_url:
                        self.pool = await asyncpg.create_pool(dsn=database_url, min_size=db_config['min_size'], max_size=db_config['max_size'])
                    else:
                        self.pool = await asyncpg.create_pool(**db_config)

                    logger.info("Database pool initialized successfully")
                    return

                except Exception as e:
                    last_exc = e
                    logger.warning(f"Database pool init attempt {attempt}/{max_attempts} failed: {e}")
                    # If this was the last attempt, log error and raise
                    if attempt == max_attempts:
                        logger.error(f"Failed to initialize database pool after {max_attempts} attempts: {e}")
                        raise

                    # Exponential backoff with jitter
                    delay = base_delay * (2 ** (attempt - 1))
                    # cap delay to 30s
                    if delay > 30:
                        delay = 30
                    await asyncio.sleep(delay)
    
    async def close(self):
        """Close the database pool"""
        _require_asyncpg()
        if self.pool:
            await self.pool.close()
            logger.info("Database pool closed")
    
    def get_connection(self):
        """Get a database connection from the pool"""
        _require_asyncpg()
        if not self.pool:
            raise RuntimeError("Database pool not initialized")
        return self.pool.acquire()

# Global database pool instance
db_pool = DatabasePool()

# =============================================================================
# NVD CVE Operations
# =============================================================================

async def ensure_cve_overview_structure() -> None:
    """Ensure the materialized view cve_overview exists with the expected structure.

    This function is idempotent and safe to run on every container start.
    It will:
    - Create the refresh_state table/seed row if missing.
    - Create or replace the refresh_cve_overview() helper.
    - Create cve_overview if missing with the union-of-sources definition and a
      table_sources text[] column. If the existing view is missing table_sources,
      it will rebuild via a swap (cve_overview_new -> cve_overview).
    - Ensure useful indexes exist (unique on cve_id required for concurrent refresh,
      published, cvss scores, is_kev, and a GIN index on table_sources).
    """
    _require_asyncpg()
    # Desired materialized view definition (WITH NO DATA for initial build)
    matview_sql = r"""
    CREATE MATERIALIZED VIEW IF NOT EXISTS cve_overview_new AS
    -- NVD rows (joined to CISA when available)
    SELECT 
        n.cve_id,
        n.published,
        n.last_modified,
        n.source,
        CASE WHEN k.cve_id IS NOT NULL THEN 'both' ELSE 'nvd' END AS table_source,
        CASE WHEN k.cve_id IS NOT NULL THEN ARRAY['nvd','cisa']::text[] ELSE ARRAY['nvd']::text[] END AS table_sources,
        CAST(n.data #>> '{cve,metrics,cvssMetricV40,0,cvssData,baseScore}' AS FLOAT) AS cvss_v40_score,
        n.data #>> '{cve,metrics,cvssMetricV40,0,cvssData,baseSeverity}' AS cvss_v40_severity,
        CAST(n.data #>> '{cve,metrics,cvssMetricV31,0,cvssData,baseScore}' AS FLOAT) AS cvss_v31_score,
        n.data #>> '{cve,metrics,cvssMetricV31,0,cvssData,baseSeverity}' AS cvss_v31_severity,
        CAST(n.data #>> '{cve,metrics,cvssMetricV30,0,cvssData,baseScore}' AS FLOAT) AS cvss_v30_score,
        n.data #>> '{cve,metrics,cvssMetricV30,0,cvssData,baseSeverity}' AS cvss_v30_severity,
        CAST(n.data #>> '{cve,metrics,cvssMetricV2,0,cvssData,baseScore}' AS FLOAT) AS cvss_v2_score,
        n.data #>> '{cve,descriptions,0,value}' AS description,
        CASE WHEN k.cve_id IS NOT NULL THEN true ELSE false END AS is_kev,
        k.date_added AS kev_date_added,
        k.required_action AS kev_required_action,
        k.due_date AS kev_due_date
    FROM nvd_cves n
    LEFT JOIN cisa_kev k ON n.cve_id = k.cve_id

    UNION ALL

    -- CISA-only rows (not present in nvd_cves)
    SELECT
        k.cve_id,
        k.date_added::timestamp AS published,
        k.date_added::timestamp AS last_modified,
        NULL AS source,
        'cisa' AS table_source,
        ARRAY['cisa']::text[] AS table_sources,
        NULL::FLOAT AS cvss_v40_score,
        NULL::TEXT AS cvss_v40_severity,
        NULL::FLOAT AS cvss_v31_score,
        NULL::TEXT AS cvss_v31_severity,
        NULL::FLOAT AS cvss_v30_score,
        NULL::TEXT AS cvss_v30_severity,
        NULL::FLOAT AS cvss_v2_score,
        k.data::text AS description,
        true AS is_kev,
        k.date_added AS kev_date_added,
        k.required_action AS kev_required_action,
        k.due_date AS kev_due_date
    FROM cisa_kev k
    WHERE NOT EXISTS (SELECT 1 FROM nvd_cves n2 WHERE n2.cve_id = k.cve_id)
    WITH NO DATA;
    """

    index_sql = [
        # Unique index required for REFRESH CONCURRENTLY
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_cve_overview_new_cve_id ON cve_overview_new (cve_id);",
        # Helpful secondary indexes
        "CREATE INDEX IF NOT EXISTS idx_cve_overview_new_published ON cve_overview_new (published);",
        "CREATE INDEX IF NOT EXISTS idx_cve_overview_new_cvss_scores ON cve_overview_new (cvss_v40_score, cvss_v31_score, cvss_v30_score, cvss_v2_score);",
        "CREATE INDEX IF NOT EXISTS idx_cve_overview_new_is_kev ON cve_overview_new (is_kev);",
        # Array membership lookups
        "CREATE INDEX IF NOT EXISTS idx_cve_overview_new_table_sources_gin ON cve_overview_new USING gin (table_sources);",
    ]

    helper_fn_sql = """
    CREATE OR REPLACE FUNCTION refresh_cve_overview()
    RETURNS void AS $$
    BEGIN
        REFRESH MATERIALIZED VIEW CONCURRENTLY cve_overview;
    END;
    $$ LANGUAGE plpgsql;
    """

    async with db_pool.get_connection() as conn:
        # Guard against concurrent ensure runs (API and ingest may both call this)
        # Use a session-level advisory lock; if we cannot acquire immediately, skip this ensure.
        _lock_key = int.from_bytes(hashlib.sha256(b'ensure_cve_overview').digest()[:8], 'big') % (2**63 - 1)
        try:
            _got_lock = await conn.fetchval('SELECT pg_try_advisory_lock($1)', _lock_key)
        except Exception:
            logger.exception('Failed to attempt advisory lock for ensure_cve_overview')
            _got_lock = False
        if not _got_lock:
            logger.info('ensure_cve_overview_structure: another process holds the advisory lock; skipping this run')
            return
        # Ensure refresh_state exists and seed row present
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS refresh_state (
                name TEXT PRIMARY KEY,
                last_refreshed TIMESTAMPTZ DEFAULT NULL
            );
            INSERT INTO refresh_state (name, last_refreshed)
            VALUES ('cve_overview', NULL)
            ON CONFLICT (name) DO NOTHING;
            """
        )

        # Ensure helper function exists
        await conn.execute(helper_fn_sql)

        # Check if the materialized view exists and whether it has table_sources
        exists = await conn.fetchval(
            "SELECT 1 FROM pg_matviews WHERE schemaname = 'public' AND matviewname = 'cve_overview'"
        )
        has_table_sources = False
        if exists:
            has_table_sources = bool(
                await conn.fetchval(
                    """
                    SELECT 1 FROM information_schema.columns
                    WHERE table_schema = 'public' AND table_name = 'cve_overview' AND column_name = 'table_sources'
                    """
                )
            )

        # Build or rebuild if needed
        if not exists or not has_table_sources:
            # Create new view definition and indexes on the _new view
            await conn.execute("DROP MATERIALIZED VIEW IF EXISTS cve_overview_new;")
            await conn.execute(matview_sql)
            for stmt in index_sql:
                await conn.execute(stmt)
            # Populate with a non-concurrent refresh (safe inside transaction)
            await conn.execute("REFRESH MATERIALIZED VIEW cve_overview_new;")
            # Swap into place
            if exists:
                await conn.execute("DROP MATERIALIZED VIEW IF EXISTS cve_overview_old;")
                await conn.execute("ALTER MATERIALIZED VIEW IF EXISTS cve_overview RENAME TO cve_overview_old;")
            await conn.execute("ALTER MATERIALIZED VIEW cve_overview_new RENAME TO cve_overview;")
            # Drop old after swap
            await conn.execute("DROP MATERIALIZED VIEW IF EXISTS cve_overview_old;")

        # Ensure required indexes exist on the current view as well (idempotent)
        await conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS ux_cve_overview_cve_id ON cve_overview (cve_id);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_overview_published ON cve_overview (published);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_overview_cvss_scores ON cve_overview (cvss_v40_score, cvss_v31_score, cvss_v30_score, cvss_v2_score);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_overview_is_kev ON cve_overview (is_kev);")
        await conn.execute("CREATE INDEX IF NOT EXISTS idx_cve_overview_table_sources_gin ON cve_overview USING gin (table_sources);")

        # Best-effort cleanup: drop any stray old/new variants left from prior runs to avoid space bloat
        try:
            rows = await conn.fetch("""
                SELECT matviewname FROM pg_matviews
                WHERE schemaname='public' AND (
                    matviewname LIKE 'cve_overview_old%' OR matviewname = 'cve_overview_new'
                )
            """)
            for r in rows:
                name = r['matviewname']
                if name == 'cve_overview':
                    continue
                # Quote identifier defensively; names here are controlled (lowercase/underscore)
                try:
                    await conn.execute(f'DROP MATERIALIZED VIEW IF EXISTS "{name}"')
                except Exception:
                    logger.exception('Failed dropping stray matview %s', name)
        except Exception:
            logger.exception('Failed scanning for stray cve_overview old/new matviews')

        # Make sure there's a row in refresh_state (done above) and leave actual refresh to runtime
        logger.info("cve_overview structure ensured (exists=%s, has_table_sources=%s)", bool(exists), bool(has_table_sources))
        # Release advisory lock
        try:
            await conn.execute('SELECT pg_advisory_unlock($1)', _lock_key)
        except Exception:
            logger.exception('Failed to release advisory lock for ensure_cve_overview')


async def store_nvd_cve(cve_id: str, published: datetime, last_modified: datetime, 
                       source: Optional[str], data: Dict[str, Any]) -> bool:
    """
    Store a single NVD CVE record
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2025-12345)
        published: Publication timestamp
        last_modified: Last modification timestamp
        source: Data source identifier
        data: Full CVE JSON data
    
    Returns:
        True if stored successfully, False otherwise
    """
    try:
        async with db_pool.get_connection() as conn:
            await conn.execute("""
                INSERT INTO nvd_cves (cve_id, published, last_modified, source, data)
                VALUES ($1, $2, $3, $4, $5)
                ON CONFLICT (cve_id) 
                DO UPDATE SET 
                    published = EXCLUDED.published,
                    last_modified = EXCLUDED.last_modified,
                    source = EXCLUDED.source,
                    data = EXCLUDED.data
                WHERE 
                    nvd_cves.published IS DISTINCT FROM EXCLUDED.published OR
                    nvd_cves.last_modified IS DISTINCT FROM EXCLUDED.last_modified OR
                    nvd_cves.source IS DISTINCT FROM EXCLUDED.source OR
                    nvd_cves.data IS DISTINCT FROM EXCLUDED.data
            """, cve_id, published, last_modified, source, json.dumps(data))
            
            logger.debug(f"Stored NVD CVE: {cve_id}")
            return True
            
    except Exception as e:
        logger.error(f"Error storing NVD CVE {cve_id}: {e}")
        return False

async def store_nvd_cves_batch(cves: List[Dict[str, Any]], conn: Any = None) -> int:
    """
    Store multiple NVD CVE records in a batch
    
    Args:
        cves: List of CVE dictionaries with keys: cve_id, published, last_modified, source, data
    
    Returns:
        Number of CVEs successfully stored
    """
    if not cves:
        return 0
    
    stored_count = 0
    batch_size = 100  # Process in batches for better performance
    
    try:
        # If a connection is provided (e.g. from AdvisoryXactLock), use it
        if conn is not None:
            for i in range(0, len(cves), batch_size):
                batch = cves[i:i + batch_size]
                for cve in batch:
                    row = await conn.fetchrow(
                        """
                        INSERT INTO nvd_cves (cve_id, published, last_modified, source, data)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (cve_id) 
                        DO UPDATE SET 
                            published = EXCLUDED.published,
                            last_modified = EXCLUDED.last_modified,
                            source = EXCLUDED.source,
                            data = EXCLUDED.data
                        WHERE 
                            nvd_cves.published IS DISTINCT FROM EXCLUDED.published OR
                            nvd_cves.last_modified IS DISTINCT FROM EXCLUDED.last_modified OR
                            nvd_cves.source IS DISTINCT FROM EXCLUDED.source OR
                            nvd_cves.data IS DISTINCT FROM EXCLUDED.data
                        RETURNING cve_id
                        """,
                        cve['cve_id'], cve['published'], cve['last_modified'], cve.get('source'), json.dumps(cve['data'])
                    )
                    if row:
                        stored_count += 1
                logger.info(f"Stored batch of {len(batch)} CVEs (running stored changes: {stored_count})")

            logger.info(f"Successfully stored {stored_count} NVD CVEs")
            # Record ingest state if any rows were stored
            if stored_count > 0:
                try:
                    await mark_source_changed('nvd', stored_count, conn=conn)
                except Exception:
                    logger.exception('Failed to mark source changed for nvd')
            return stored_count

        # Otherwise use pool-managed connections as before
        async with db_pool.get_connection() as pool_conn:
            for i in range(0, len(cves), batch_size):
                batch = cves[i:i + batch_size]
                for cve in batch:
                    row = await pool_conn.fetchrow(
                        """
                        INSERT INTO nvd_cves (cve_id, published, last_modified, source, data)
                        VALUES ($1, $2, $3, $4, $5)
                        ON CONFLICT (cve_id) 
                        DO UPDATE SET 
                            published = EXCLUDED.published,
                            last_modified = EXCLUDED.last_modified,
                            source = EXCLUDED.source,
                            data = EXCLUDED.data
                        WHERE 
                            nvd_cves.published IS DISTINCT FROM EXCLUDED.published OR
                            nvd_cves.last_modified IS DISTINCT FROM EXCLUDED.last_modified OR
                            nvd_cves.source IS DISTINCT FROM EXCLUDED.source OR
                            nvd_cves.data IS DISTINCT FROM EXCLUDED.data
                        RETURNING cve_id
                        """,
                        cve['cve_id'], cve['published'], cve['last_modified'], cve.get('source'), json.dumps(cve['data'])
                    )
                    if row:
                        stored_count += 1
                logger.info(f"Stored batch of {len(batch)} CVEs (running stored changes: {stored_count})")

        logger.info(f"Successfully stored {stored_count} NVD CVEs")
        if stored_count > 0:
            try:
                await mark_source_changed('nvd', stored_count)
            except Exception:
                logger.exception('Failed to mark source changed for nvd')
        return stored_count

    except Exception as e:
        logger.error(f"Error in batch storage: {e}")
        return stored_count


# -----------------------------------------------------------------------------
# Scheduler flags helpers (simple key/value table stored in the DB)
# These are used to enable/disable scheduled tasks at runtime without
# rebuilding containers. The table is created lazily if missing.
# -----------------------------------------------------------------------------
async def _ensure_scheduler_flags_table(conn):
    # Create table if missing
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS scheduler_flags (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL,
            updated_at TIMESTAMP WITHOUT TIME ZONE DEFAULT now(),
            updated_by TEXT,
            updated_reason TEXT
        )
    """)

    # Ensure audit columns exist for older deployments with an existing table
    # Use IF NOT EXISTS to be idempotent and safe to run repeatedly.
    await conn.execute("ALTER TABLE scheduler_flags ADD COLUMN IF NOT EXISTS updated_by TEXT")
    await conn.execute("ALTER TABLE scheduler_flags ADD COLUMN IF NOT EXISTS updated_reason TEXT")


async def set_scheduler_flag(key: str, value: str, updated_by: Optional[str] = None, updated_reason: Optional[str] = None):
    """Set a scheduler flag (string value). Creates table if missing.

    Records optional audit information: who updated the flag and a reason.
    """
    _require_asyncpg()
    async with db_pool.get_connection() as conn:
        try:
            await _ensure_scheduler_flags_table(conn)
            await conn.execute(
                """
                INSERT INTO scheduler_flags (key, value, updated_by, updated_reason)
                VALUES ($1, $2, $3, $4)
                ON CONFLICT (key) DO UPDATE SET
                    value = EXCLUDED.value,
                    updated_at = now(),
                    updated_by = EXCLUDED.updated_by,
                    updated_reason = EXCLUDED.updated_reason
                """,
                key, value, updated_by, updated_reason
            )
            return True
        except Exception:
            logger.exception('Failed to set scheduler flag %s', key)
            return False


async def get_scheduler_flag(key: str) -> Optional[str]:
    """Get a scheduler flag value as string. Returns None if not set."""
    _require_asyncpg()
    async with db_pool.get_connection() as conn:
        try:
            await _ensure_scheduler_flags_table(conn)
            row = await conn.fetchrow('SELECT value FROM scheduler_flags WHERE key = $1', key)
            return row['value'] if row else None
        except Exception:
            logger.exception('Failed to read scheduler flag %s', key)
            return None


async def get_scheduler_flag_row(key: str) -> Optional[Dict[str, Any]]:
    """Get full scheduler flag row including audit fields.

    Returns a dict: { 'key', 'value', 'updated_at', 'updated_by', 'updated_reason' }
    or None if not present.
    """
    _require_asyncpg()
    async with db_pool.get_connection() as conn:
        try:
            await _ensure_scheduler_flags_table(conn)
            row = await conn.fetchrow('SELECT key, value, updated_at, updated_by, updated_reason FROM scheduler_flags WHERE key = $1', key)
            if not row:
                return None
            return {
                'key': row['key'],
                'value': row['value'],
                'updated_at': row['updated_at'],
                'updated_by': row.get('updated_by'),
                'updated_reason': row.get('updated_reason')
            }
        except Exception:
            logger.exception('Failed to read scheduler flag row %s', key)
            return None

async def get_nvd_cve(cve_id: str) -> Optional[Dict[str, Any]]:
    """
    Retrieve a single NVD CVE by ID
    
    Args:
        cve_id: CVE identifier
    
    Returns:
        CVE record dict or None if not found
    """
    try:
        async with db_pool.get_connection() as conn:
            row = await conn.fetchrow("""
                SELECT cve_id, published, last_modified, source, data
                FROM nvd_cves 
                WHERE cve_id = $1
            """, cve_id)
            
            if row:
                return {
                    'cve_id': row['cve_id'],
                    'published': row['published'],
                    'last_modified': row['last_modified'],
                    'source': row['source'],
                    'data': row['data']  # Already parsed as dict
                }
            return None
            
    except Exception as e:
        logger.error(f"Error retrieving CVE {cve_id}: {e}")
        return None

# =============================================================================
# CISA KEV Operations
# =============================================================================

async def store_cisa_kev(cve_id: str, vendor_project: Optional[str], product: Optional[str],
                        date_added: datetime, required_action: Optional[str], 
                        due_date: Optional[datetime], data: Dict[str, Any]) -> bool:
    """
    Store a single CISA KEV record
    
    Args:
        cve_id: CVE identifier
        vendor_project: Vendor/project name
        product: Product name
        date_added: Date added to KEV
        required_action: Required action text
        due_date: Due date for action
        data: Full KEV JSON data
    
    Returns:
        True if stored successfully, False otherwise
    """
    try:
        async with db_pool.get_connection() as conn:
            await conn.execute("""
                INSERT INTO cisa_kev (cve_id, vendor_project, product, date_added, 
                                     required_action, due_date, data)
                VALUES ($1, $2, $3, $4, $5, $6, $7)
                ON CONFLICT (cve_id) 
                DO UPDATE SET 
                    vendor_project = EXCLUDED.vendor_project,
                    product = EXCLUDED.product,
                    date_added = EXCLUDED.date_added,
                    required_action = EXCLUDED.required_action,
                    due_date = EXCLUDED.due_date,
                    data = EXCLUDED.data
                WHERE 
                    cisa_kev.vendor_project IS DISTINCT FROM EXCLUDED.vendor_project OR
                    cisa_kev.product IS DISTINCT FROM EXCLUDED.product OR
                    cisa_kev.date_added IS DISTINCT FROM EXCLUDED.date_added OR
                    cisa_kev.required_action IS DISTINCT FROM EXCLUDED.required_action OR
                    cisa_kev.due_date IS DISTINCT FROM EXCLUDED.due_date OR
                    cisa_kev.data IS DISTINCT FROM EXCLUDED.data
            """, cve_id, vendor_project, product, date_added, required_action, 
                 due_date, json.dumps(data))
            
            logger.debug(f"Stored CISA KEV: {cve_id}")
            return True
            
    except Exception as e:
        logger.error(f"Error storing CISA KEV {cve_id}: {e}")
        return False

async def store_cisa_kevs_batch(kevs: List[Dict[str, Any]], conn: Any = None) -> int:
    """
    Store multiple CISA KEV records in a batch
    
    Args:
        kevs: List of KEV dictionaries
    
    Returns:
        Number of KEVs successfully stored
    """
    if not kevs:
        return 0

    stored_count = 0
    batch_size = 100

    def extract_fields(k):
        # Defensive extraction for CISA KEV fields
        return (
            k.get('cve_id') or k.get('cveID'),
            k.get('vendor_project') or k.get('vendorProject'),
            k.get('product'),
            k.get('date_added'),
            k.get('required_action'),
            k.get('due_date'),
            json.dumps(k.get('data', {}))
        )

    try:
        if conn is not None:
            for i in range(0, len(kevs), batch_size):
                batch = kevs[i:i + batch_size]
                for k in batch:
                    (cve_id, vendor_project, product, date_added, required_action, due_date, data_json) = extract_fields(k)
                    row = await conn.fetchrow(
                        """
                        INSERT INTO cisa_kev (cve_id, vendor_project, product, date_added, required_action, due_date, data)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ON CONFLICT (cve_id)
                        DO UPDATE SET 
                            vendor_project = EXCLUDED.vendor_project,
                            product = EXCLUDED.product,
                            date_added = EXCLUDED.date_added,
                            required_action = EXCLUDED.required_action,
                            due_date = EXCLUDED.due_date,
                            data = EXCLUDED.data
                        WHERE 
                            cisa_kev.vendor_project IS DISTINCT FROM EXCLUDED.vendor_project OR
                            cisa_kev.product IS DISTINCT FROM EXCLUDED.product OR
                            cisa_kev.date_added IS DISTINCT FROM EXCLUDED.date_added OR
                            cisa_kev.required_action IS DISTINCT FROM EXCLUDED.required_action OR
                            cisa_kev.due_date IS DISTINCT FROM EXCLUDED.due_date OR
                            cisa_kev.data IS DISTINCT FROM EXCLUDED.data
                        RETURNING cve_id
                        """,
                        cve_id, vendor_project, product, date_added, required_action, due_date, data_json
                    )
                    if row:
                        stored_count += 1
                logger.info(f"Stored batch of {len(batch)} CISA KEVs (running stored changes: {stored_count})")

            logger.info(f"Successfully stored {stored_count} CISA KEVs")
            if stored_count > 0:
                try:
                    await mark_source_changed('cisa', stored_count, conn=conn)
                except Exception:
                    logger.exception('Failed to mark source changed for cisa')
            return stored_count

        async with db_pool.get_connection() as pool_conn:
            for i in range(0, len(kevs), batch_size):
                batch = kevs[i:i + batch_size]
                for k in batch:
                    (cve_id, vendor_project, product, date_added, required_action, due_date, data_json) = extract_fields(k)
                    row = await pool_conn.fetchrow(
                        """
                        INSERT INTO cisa_kev (cve_id, vendor_project, product, date_added, required_action, due_date, data)
                        VALUES ($1, $2, $3, $4, $5, $6, $7)
                        ON CONFLICT (cve_id)
                        DO UPDATE SET 
                            vendor_project = EXCLUDED.vendor_project,
                            product = EXCLUDED.product,
                            date_added = EXCLUDED.date_added,
                            required_action = EXCLUDED.required_action,
                            due_date = EXCLUDED.due_date,
                            data = EXCLUDED.data
                        WHERE 
                            cisa_kev.vendor_project IS DISTINCT FROM EXCLUDED.vendor_project OR
                            cisa_kev.product IS DISTINCT FROM EXCLUDED.product OR
                            cisa_kev.date_added IS DISTINCT FROM EXCLUDED.date_added OR
                            cisa_kev.required_action IS DISTINCT FROM EXCLUDED.required_action OR
                            cisa_kev.due_date IS DISTINCT FROM EXCLUDED.due_date OR
                            cisa_kev.data IS DISTINCT FROM EXCLUDED.data
                        RETURNING cve_id
                        """,
                        cve_id, vendor_project, product, date_added, required_action, due_date, data_json
                    )
                    if row:
                        stored_count += 1
                logger.info(f"Stored batch of {len(batch)} CISA KEVs (running stored changes: {stored_count})")

        logger.info(f"Successfully stored {stored_count} CISA KEVs")
        if stored_count > 0:
            try:
                await mark_source_changed('cisa', stored_count)
            except Exception:
                logger.exception('Failed to mark source changed for cisa')
        return stored_count
    except Exception as e:
        logger.error(f"Error storing CISA KEVs: {e}")
        return stored_count

# =============================================================================
# Query Operations
# =============================================================================

async def search_cves(
    query: Optional[str] = None,
    min_score: Optional[float] = None,
    max_score: Optional[float] = None,
    severity: Optional[str] = None,
    severity_in: Optional[List[str]] = None,
    has_kev: Optional[bool] = None,
    date_from: Optional[datetime] = None,
    date_to: Optional[datetime] = None,
    last_modified_from: Optional[datetime] = None,
    last_modified_to: Optional[datetime] = None,
    sources: Optional[List[str]] = None,
    cve_id: Optional[str] = None,
    cve_id_contains: Optional[str] = None,
    sort_by: Optional[str] = None,
    sort_dir: Optional[str] = None,
    limit: int = 50,
    offset: int = 0
) -> Dict[str, Any]:
    """
    Search CVEs using the materialized view with JSONB flexibility
    
    Args:
        query: Text search in description
        min_score: Minimum CVSS score (any version)
        max_score: Maximum CVSS score (any version)
        severity: CVSS severity level
        has_kev: Filter by KEV status
        date_from: Published date range start
        date_to: Published date range end
        limit: Maximum results to return
        offset: Results offset for pagination
    
    Returns:
        Dict with 'cves', 'total_count', 'limit', 'offset'
    """
    conditions = []
    params = []
    param_idx = 1
    
    # Build WHERE conditions
    if query:
        # Search in description and allow quick CVE ID search too
        conditions.append(f"(description ILIKE ${param_idx} OR cve_id ILIKE ${param_idx})")
        params.append(f"%{query}%")
        param_idx += 1

    if cve_id:
        conditions.append(f"cve_id = ${param_idx}")
        params.append(cve_id.upper())
        param_idx += 1

    if cve_id_contains and not cve_id:
        conditions.append(f"cve_id ILIKE ${param_idx}")
        params.append(f"%{cve_id_contains}%")
        param_idx += 1
    
    if min_score is not None:
        conditions.append(f"""(
            cvss_v40_score >= ${param_idx} OR 
            cvss_v31_score >= ${param_idx} OR 
            cvss_v30_score >= ${param_idx} OR 
            cvss_v2_score >= ${param_idx}
        )""")
        params.append(min_score)
        param_idx += 1
    
    if max_score is not None:
        conditions.append(f"""(
            (cvss_v40_score IS NULL OR cvss_v40_score <= ${param_idx}) AND
            (cvss_v31_score IS NULL OR cvss_v31_score <= ${param_idx}) AND
            (cvss_v30_score IS NULL OR cvss_v30_score <= ${param_idx}) AND
            (cvss_v2_score IS NULL OR cvss_v2_score <= ${param_idx})
        )""")
        params.append(max_score)
        param_idx += 1
    
    if severity:
        conditions.append(f"""(
            cvss_v40_severity = ${param_idx} OR 
            cvss_v31_severity = ${param_idx} OR 
            cvss_v30_severity = ${param_idx}
        )""")
        params.append(severity.upper())
        param_idx += 1

    if severity_in:
        sev_list = [s.upper() for s in severity_in]
        conditions.append(f"""(
            cvss_v40_severity = ANY(${param_idx}::text[]) OR 
            cvss_v31_severity = ANY(${param_idx}::text[]) OR 
            cvss_v30_severity = ANY(${param_idx}::text[])
        )""")
        params.append(sev_list)
        param_idx += 1
    
    if has_kev is not None:
        conditions.append(f"is_kev = ${param_idx}")
        params.append(has_kev)
        param_idx += 1
    
    if date_from:
        conditions.append(f"published >= ${param_idx}")
        params.append(date_from)
        param_idx += 1
    
    if date_to:
        conditions.append(f"published <= ${param_idx}")
        params.append(date_to)
        param_idx += 1

    if last_modified_from:
        conditions.append(f"last_modified >= ${param_idx}")
        params.append(last_modified_from)
        param_idx += 1

    if last_modified_to:
        conditions.append(f"last_modified <= ${param_idx}")
        params.append(last_modified_to)
        param_idx += 1

    if sources:
        # Filter by membership in table_sources array (e.g., ['nvd'], ['cisa'], ['nvd','cisa'])
        conditions.append(f"table_sources && ${param_idx}::text[]")
        params.append([s.lower() for s in sources])
        param_idx += 1
    
    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)
    
    # Sorting: whitelist columns
    allowed_sort_cols = {
        'published': 'published',
        'last_modified': 'last_modified',
        'cvss_v40_score': 'cvss_v40_score',
        'cvss_v31_score': 'cvss_v31_score',
        'cvss_v30_score': 'cvss_v30_score',
        'cvss_v2_score': 'cvss_v2_score',
        'kev_date_added': 'kev_date_added',
        'is_kev': 'is_kev',
        'cve_id': 'cve_id'
    }
    sort_col = allowed_sort_cols.get((sort_by or '').lower()) if sort_by else None
    sort_direction = 'DESC' if (sort_dir or '').lower() in ('desc', 'd') else 'ASC'

    try:
        async with db_pool.get_connection() as conn:
            # Use the materialized view `cve_overview` which now contains both
            # NVD rows (joined with CISA) and CISA-only rows (via UNION in the
            # matview definition). This is faster for reads when the matview is
            # kept refreshed.

            order_clause = "ORDER BY GREATEST(COALESCE(published, to_timestamp(0)), COALESCE(last_modified, to_timestamp(0))) DESC"
            if sort_col:
                order_clause = f"ORDER BY {sort_col} {sort_direction} NULLS LAST, cve_id ASC"

            results_query = f"""
                SELECT * FROM cve_overview
                {where_clause}
                {order_clause}
                LIMIT ${param_idx} OFFSET ${param_idx + 1}
            """
            params_with_paging = list(params) + [limit, offset]

            # Fetch page results first, with a modest statement timeout to stay responsive
            try:
                async with conn.transaction():
                    await conn.execute("SET LOCAL statement_timeout = '5000ms'")
                    rows = await conn.fetch(results_query, *params_with_paging)
            except Exception as e:
                logger.error(f"Error fetching CVE page results: {e}")
                return {
                    'cves': [],
                    'total_count': 0,
                    'limit': limit,
                    'offset': offset
                }

            cves = [dict(row) for row in rows]

            # Count may be expensive; bound it with a short statement_timeout
            total_count = None
            count_query = f"SELECT COUNT(*) FROM cve_overview {where_clause}"
            try:
                async with conn.transaction():
                    await conn.execute("SET LOCAL statement_timeout = '2000ms'")
                    total_count = await conn.fetchval(count_query, *params)
            except Exception as e:
                logger.warning(f"COUNT(*) timed out or failed; returning without exact total: {e}")

            # If count unavailable, approximate to keep pagination flowing
            count_incomplete = False
            if total_count is None:
                count_incomplete = True
                total_count = offset + len(cves) + (1 if len(cves) == limit else 0)

            return {
                'cves': cves,
                'total_count': total_count,
                'limit': limit,
                'offset': offset,
                'count_incomplete': count_incomplete
            }
    
    except Exception as e:
        logger.error(f"Error searching CVEs: {e}")
        return {
            'cves': [],
            'total_count': 0,
            'limit': limit,
            'offset': offset
        }

async def get_database_stats() -> Dict[str, Any]:
    """
    Get basic database statistics
    
    Returns:
        Dict with counts and basic stats
    """
    try:
        async with db_pool.get_connection() as conn:
            # Get counts
            nvd_count = await conn.fetchval("SELECT COUNT(*) FROM nvd_cves")
            kev_count = await conn.fetchval("SELECT COUNT(*) FROM cisa_kev")
            
            # Get recent activity
            recent_nvd = await conn.fetchval("""
                SELECT COUNT(*) FROM nvd_cves 
                WHERE published >= NOW() - INTERVAL '30 days'
            """)
            
            return {
                'nvd_cves_total': nvd_count,
                'cisa_kevs_total': kev_count,
                'recent_cves_30_days': recent_nvd,
                # Present last_updated in configured timezone for human consumption
                'last_updated': datetime.utcnow().replace(tzinfo=zoneinfo.ZoneInfo('UTC')).astimezone(TZINFO).isoformat()
            }
    
    except Exception as e:
        logger.error(f"Error getting database stats: {e}")
        return {
            'nvd_cves_total': 0,
            'cisa_kevs_total': 0,
            'recent_cves_30_days': 0,
            'last_updated': datetime.utcnow().isoformat()
        }

async def refresh_materialized_view(retries: int = 2) -> bool:
    """
    Refresh the cve_overview materialized view with small retry/backoff.

    Returns True if successful.
    """
    attempt = 0
    delay_seq = [2, 5, 10]
    while True:
        attempt += 1
        try:
            async with db_pool.get_connection() as conn:
                try:
                    await conn.execute("SELECT refresh_cve_overview()")
                    logger.info("Materialized view refreshed successfully (attempt %d)", attempt)
                    try:
                        await _update_refresh_state('cve_overview')
                    except Exception:
                        logger.exception('Failed to update refresh_state after refresh')
                    return True
                except Exception as e:
                    msg = str(e)
                    if "cannot refresh materialized view" in msg and "concurrently" in msg:
                        logger.warning("Concurrent refresh contention (attempt %d): %s", attempt, msg)
                    else:
                        logger.warning("Refresh attempt %d failed: %s", attempt, msg)
        except Exception as e:
            logger.warning("Refresh connection error on attempt %d: %s", attempt, e)

        if attempt > max(1, retries):
            logger.error("Giving up refreshing materialized view after %d attempts", attempt-1)
            return False
        await asyncio.sleep(delay_seq[min(attempt-1, len(delay_seq)-1)])


async def get_cve_overview_total() -> int:
    """Return total number of rows in cve_overview materialized view."""
    try:
        async with db_pool.get_connection() as conn:
            cnt = await conn.fetchval('SELECT COUNT(*) FROM cve_overview')
            return int(cnt or 0)
    except Exception:
        logger.exception('Failed to get cve_overview total')
        return 0


async def mark_source_changed(source: str, stored_count: int, conn: Any = None) -> None:
    """Record that a source inserted/updated rows and when it last changed.

    If a connection is provided, use it (so the update can be part of the
    same transaction). Otherwise acquire a pool connection.
    """
    sql = """
    INSERT INTO ingest_state (source, last_changed, last_stored_count, last_run)
    VALUES ($1, NOW(), $2, NOW())
    ON CONFLICT (source) DO UPDATE SET
      last_changed = EXCLUDED.last_changed,
      last_stored_count = EXCLUDED.last_stored_count,
      last_run = EXCLUDED.last_run
    """
    try:
        if conn is not None:
            await conn.execute(sql, source, stored_count)
        else:
            async with db_pool.get_connection() as pool_conn:
                await pool_conn.execute(sql, source, stored_count)
        logger.debug(f"Marked source changed: {source} (+{stored_count})")
    except Exception:
        logger.exception(f"Failed to mark source changed for: {source}")


async def get_ingest_state(source: str) -> Dict[str, Any]:
    """Return ingest state for a source."""
    try:
        async with db_pool.get_connection() as conn:
            row = await conn.fetchrow("SELECT source, last_changed, last_stored_count, last_run FROM ingest_state WHERE source = $1", source)
            if row:
                out = dict(row)
                # convert times to presentation TZ if present
                for k in ('last_changed', 'last_run'):
                    if out.get(k):
                        try:
                            out[k] = out[k].replace(tzinfo=zoneinfo.ZoneInfo('UTC')).astimezone(TZINFO).isoformat()
                        except Exception:
                            out[k] = str(out[k])
                return out
            return {
                'source': source,
                'last_changed': None,
                'last_stored_count': 0,
                'last_run': None
            }
    except Exception:
        logger.exception('Error getting ingest state')
        return {
            'source': source,
            'last_changed': None,
            'last_stored_count': 0,
            'last_run': None
        }


async def get_all_ingest_state() -> List[Dict[str, Any]]:
    """Return state rows for all sources."""
    try:
        async with db_pool.get_connection() as conn:
            rows = await conn.fetch("SELECT source, last_changed, last_stored_count, last_run FROM ingest_state")
            out = []
            for r in rows:
                d = dict(r)
                for k in ('last_changed', 'last_run'):
                    if d.get(k):
                        try:
                            d[k] = d[k].replace(tzinfo=zoneinfo.ZoneInfo('UTC')).astimezone(TZINFO).isoformat()
                        except Exception:
                            d[k] = str(d[k])
                out.append(d)
            return out
    except Exception:
        logger.exception('Error getting all ingest state')
        return []


async def get_refresh_state(name: str) -> Dict[str, Any]:
    try:
        async with db_pool.get_connection() as conn:
            row = await conn.fetchrow("SELECT name, last_refreshed FROM refresh_state WHERE name = $1", name)
            if row:
                out = dict(row)
                if out.get('last_refreshed'):
                    try:
                        out['last_refreshed'] = out['last_refreshed'].replace(tzinfo=zoneinfo.ZoneInfo('UTC')).astimezone(TZINFO).isoformat()
                    except Exception:
                        out['last_refreshed'] = str(out['last_refreshed'])
                return out
            return {'name': name, 'last_refreshed': None}
    except Exception:
        logger.exception('Error getting refresh state')
        return {'name': name, 'last_refreshed': None}


async def _update_refresh_state(name: str) -> None:
    try:
        async with db_pool.get_connection() as conn:
            await conn.execute("UPDATE refresh_state SET last_refreshed = NOW() WHERE name = $1", name)
            logger.debug(f"Updated refresh_state for {name}")
    except Exception:
        logger.exception('Failed to update refresh_state')


async def cleanup_duplicates() -> Dict[str, Any]:
    """Scan user tables for duplicate rows and remove duplicates keeping one.

    Returns a report mapping table name -> {checked: N, removed: M}
    """
    report = {}
    try:
        async with db_pool.get_connection() as conn:
            # Get list of user tables in public schema (excluding migrations and meta tables)
            tables = await conn.fetch("""
                SELECT table_name FROM information_schema.tables
                WHERE table_schema = 'public' AND table_type = 'BASE TABLE'
            """)

            for r in tables:
                table = r['table_name']
                # Skip internal tables we know should not be touched
                if table in ('ingest_state', 'refresh_state'):
                    continue

                # Check for primary key columns
                pk = await conn.fetchrow("""
                    SELECT a.attname as column_name
                    FROM pg_index i
                    JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = ANY(i.indkey)
                    WHERE i.indrelid = $1::regclass AND i.indisprimary
                """, table)

                if pk:
                    pk_col = pk['column_name']
                    # Remove duplicate PK rows by keeping the first (min ctid)
                    # Count duplicates
                    dup_count = await conn.fetchval(f"SELECT COUNT(*) FROM (SELECT {pk_col}, COUNT(*) FROM {table} GROUP BY {pk_col} HAVING COUNT(*) > 1) s")
                    removed = 0
                    if dup_count and dup_count > 0:
                        # Delete duplicates keeping lowest ctid per pk
                        res = await conn.execute(f"""
                            DELETE FROM {table} t
                            USING (
                                SELECT ctid, {pk_col}, row_number() OVER (PARTITION BY {pk_col} ORDER BY ctid) rn
                                FROM {table}
                            ) d
                            WHERE t.ctid = d.ctid AND d.rn > 1
                        """)
                        # asyncpg returns command tag like 'DELETE <n>'
                        try:
                            removed = int(res.split()[-1])
                        except Exception:
                            removed = 0

                    report[table] = {'duplicates_groups': dup_count or 0, 'removed': removed}
                else:
                    # No PK: dedup by entire row (hash) — expensive, so sample first
                    # We'll create a temp table of hashes and delete duplicates keeping first
                    await conn.execute(f"CREATE TEMP TABLE IF NOT EXISTS tmp_hashes_{table} (h TEXT, ctid tid) ON COMMIT DROP")
                    await conn.execute(f"INSERT INTO tmp_hashes_{table} (h, ctid) SELECT md5(CAST(t.* AS text)), ctid FROM {table} t")
                    dup_groups = await conn.fetchval(f"SELECT COUNT(*) FROM (SELECT h FROM tmp_hashes_{table} GROUP BY h HAVING COUNT(*) > 1) s")
                    removed = 0
                    if dup_groups and dup_groups > 0:
                        res = await conn.execute(f"DELETE FROM {table} t USING tmp_hashes_{table} h WHERE t.ctid = h.ctid AND (SELECT COUNT(*) FROM tmp_hashes_{table} th WHERE th.h = h.h AND th.ctid < h.ctid) > 0")
                        try:
                            removed = int(res.split()[-1])
                        except Exception:
                            removed = 0
                    report[table] = {'duplicates_groups': dup_groups or 0, 'removed': removed}

    except Exception:
        logger.exception('Error during cleanup_duplicates')
        raise

    return report


async def record_crawl_run_start(run_id: str, source: str, first_total: int = None) -> None:
    """Insert a crawl_runs row when a run starts. Optionally persist the adapter-reported
    `first_total` (the totalResults from the first page) for full-round runs.
    """
    try:
        async with db_pool.get_connection() as conn:
            if first_total is None:
                await conn.execute(
                    "INSERT INTO crawl_runs (run_id, source, started_at, status) VALUES ($1, $2, NOW(), 'running') ON CONFLICT (run_id) DO NOTHING",
                    run_id, source
                )
            else:
                await conn.execute(
                    "INSERT INTO crawl_runs (run_id, source, started_at, status, first_total) VALUES ($1, $2, NOW(), 'running', $3) ON CONFLICT (run_id) DO NOTHING",
                    run_id, source, first_total
                )
    except Exception:
        logger.exception('Failed to record crawl run start')


async def record_crawl_run_finish(run_id: str, status: str, stored_count: int = 0, message: str = None) -> None:
    """Update a crawl_runs row when a run finishes."""
    try:
        async with db_pool.get_connection() as conn:
            await conn.execute(
                "UPDATE crawl_runs SET finished_at = NOW(), status = $2, stored_count = $3, error = $4 WHERE run_id = $1",
                run_id, status, stored_count, message
            )
    except Exception:
        logger.exception('Failed to record crawl run finish')


async def get_recent_crawl_runs(limit: int = 10) -> List[Dict[str, Any]]:
    """Return recent crawl_runs ordered by started_at desc."""
    try:
        async with db_pool.get_connection() as conn:
            rows = await conn.fetch("SELECT run_id, source, started_at, finished_at, status, stored_count, error, first_total FROM crawl_runs ORDER BY started_at DESC LIMIT $1", limit)
            out = []
            for r in rows:
                d = dict(r)
                # include first_total if present
                if 'first_total' in d:
                    d['first_total'] = d.get('first_total')
                for k in ('started_at', 'finished_at'):
                    if d.get(k):
                        try:
                            d[k] = d[k].replace(tzinfo=zoneinfo.ZoneInfo('UTC')).astimezone(TZINFO).isoformat()
                        except Exception:
                            d[k] = str(d[k])
                out.append(d)
            return out
    except Exception:
        logger.exception('Failed to fetch recent crawl runs')
        return []


async def get_last_successful_finish_at(source: str):
    """Return the latest finished_at (as a Python datetime) for a successful crawl of a source.

    This returns the raw datetime from PostgreSQL without converting it to a string
    or changing timezones so that scheduler code can do datetime arithmetic reliably.
    """
    try:
        async with db_pool.get_connection() as conn:
            row = await conn.fetchrow(
                """
                SELECT finished_at
                FROM crawl_runs
                WHERE source = $1 AND status = 'success' AND finished_at IS NOT NULL
                ORDER BY finished_at DESC
                LIMIT 1
                """,
                source,
            )
            if row:
                return row[0]
            return None
    except Exception:
        logger.exception('Failed to fetch last successful finished_at for %s', source)
        return None
async def get_last_attempt_at(source: str):
    """Return the latest started_at for any crawl run attempt for a source."""
    try:
        async with db_pool.get_connection() as conn:
            row = await conn.fetchrow(
                """
                SELECT started_at, finished_at, status
                FROM crawl_runs
                WHERE source = $1
                ORDER BY started_at DESC
                LIMIT 1
                """,
                source,
            )
            return dict(row) if row else None
    except Exception:
        logger.exception('Failed to fetch last attempt for %s', source)
        return None


async def get_fetch_log(source: Optional[str] = None, limit: int = 10) -> List[Dict[str, Any]]:
    """Return latest crawl_runs entries, optionally filtered by source."""
    try:
        async with db_pool.get_connection() as conn:
            if source:
                rows = await conn.fetch(
                    """
                    SELECT run_id, source, started_at, finished_at, status, stored_count, error, first_total
                    FROM crawl_runs
                    WHERE source = $1
                    ORDER BY started_at DESC
                    LIMIT $2
                    """,
                    source, limit,
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT run_id, source, started_at, finished_at, status, stored_count, error, first_total
                    FROM crawl_runs
                    ORDER BY started_at DESC
                    LIMIT $1
                    """,
                    limit,
                )
            out = []
            for r in rows:
                d = dict(r)
                for k in ('started_at', 'finished_at'):
                    if d.get(k):
                        try:
                            d[k] = d[k].replace(tzinfo=zoneinfo.ZoneInfo('UTC')).astimezone(TZINFO).isoformat()
                        except Exception:
                            d[k] = str(d[k])
                out.append(d)
            return out
    except Exception:
        logger.exception('Failed to fetch crawl log')
        return []


# -----------------------------------------------------------------------------
# One-time job scheduling helpers (lightweight, DB-backed)
# -----------------------------------------------------------------------------

async def ensure_one_time_jobs_table() -> None:
    _require_asyncpg()
    async with db_pool.get_connection() as conn:
        await conn.execute(
            """
            CREATE TABLE IF NOT EXISTS one_time_jobs (
                id UUID PRIMARY KEY,
                source TEXT NOT NULL,
                run_at TIMESTAMPTZ NOT NULL,
                params JSONB,
                status TEXT NOT NULL DEFAULT 'scheduled',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                started_at TIMESTAMPTZ,
                finished_at TIMESTAMPTZ,
                error TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_one_time_jobs_status_runat ON one_time_jobs (status, run_at);
            """
        )


async def create_one_time_job(source: str, run_at: datetime, params: Dict[str, Any] | None = None) -> Dict[str, Any]:
    _require_asyncpg()
    await ensure_one_time_jobs_table()
    job_id = uuid.uuid4()
    async with db_pool.get_connection() as conn:
        await conn.execute(
            """
            INSERT INTO one_time_jobs (id, source, run_at, params, status)
            VALUES ($1, $2, $3, $4, 'scheduled')
            """,
            job_id, source, run_at, json.dumps(params or {}),
        )
        return {'id': str(job_id), 'source': source, 'run_at': run_at.isoformat(), 'status': 'scheduled', 'params': params or {}}


async def get_due_one_time_jobs(limit: int = 10) -> List[Dict[str, Any]]:
    _require_asyncpg()
    async with db_pool.get_connection() as conn:
        rows = await conn.fetch(
            """
            SELECT id, source, run_at, params, status
            FROM one_time_jobs
            WHERE status = 'scheduled' AND run_at <= NOW()
            ORDER BY run_at ASC
            LIMIT $1
            """,
            limit,
        )
        out = []
        for r in rows:
            d = dict(r)
            try:
                d['params'] = d['params'] or {}
            except Exception:
                pass
            out.append(d)
        return out


async def mark_job_started(job_id: str) -> bool:
    _require_asyncpg()
    async with db_pool.get_connection() as conn:
        res = await conn.execute(
            """
            UPDATE one_time_jobs
            SET status = 'running', started_at = NOW()
            WHERE id = $1 AND status = 'scheduled'
            """,
            uuid.UUID(job_id),
        )
        try:
            return res.split()[-1] == '1'
        except Exception:
            return False


async def mark_job_finished(job_id: str, success: bool, error: Optional[str] = None) -> None:
    _require_asyncpg()
    async with db_pool.get_connection() as conn:
        status = 'success' if success else 'failed'
        await conn.execute(
            """
            UPDATE one_time_jobs
            SET status = $2, finished_at = NOW(), error = $3
            WHERE id = $1
            """,
            uuid.UUID(job_id), status, error,
        )


async def record_crawl_run_set_first_total(run_id: str, first_total: int) -> None:
    """Set the first_total field for a crawl run after the run has started."""
    try:
        async with db_pool.get_connection() as conn:
            await conn.execute(
                "UPDATE crawl_runs SET first_total = $2 WHERE run_id = $1",
                run_id, first_total
            )
    except Exception:
        logger.exception('Failed to set first_total for crawl run')


async def insert_crawl_run_verification(run_id: str, first_total: int, db_count: int, ok: bool, note: str = None) -> None:
    try:
        async with db_pool.get_connection() as conn:
            await conn.execute(
                "INSERT INTO crawl_run_verifications (run_id, first_total, db_count, ok, note) VALUES ($1, $2, $3, $4, $5)",
                run_id, first_total, db_count, ok, note
            )
    except Exception:
        logger.exception('Failed to insert crawl run verification')


async def verify_crawl_run_counts(run_id: str) -> bool:
    """Compare the first_total stored for a run with the current DB count and insert a verification row.

    Returns True if counts match or first_total is NULL, False if mismatch.
    """
    try:
        async with db_pool.get_connection() as conn:
            row = await conn.fetchrow('SELECT first_total FROM crawl_runs WHERE run_id = $1', run_id)
            if not row or row.get('first_total') is None:
                # Nothing to verify
                await insert_crawl_run_verification(run_id, None, None, True, 'no first_total present')
                return True
            first_total = row.get('first_total')
            db_count = await conn.fetchval('SELECT COUNT(*) FROM nvd_cves')
            ok = (db_count == first_total)
            note = None
            if not ok:
                note = f'db_count {db_count} != first_total {first_total}'
            await insert_crawl_run_verification(run_id, first_total, db_count, ok, note)
            return ok
    except Exception:
        logger.exception('Failed to verify crawl run counts')
        return False


async def is_source_running(source: str) -> bool:
    """Return True if there's a crawl_runs row for source with status 'running'."""
    try:
        async with db_pool.get_connection() as conn:
            cnt = await conn.fetchval("SELECT COUNT(*) FROM crawl_runs WHERE source = $1 AND status = 'running'", source)
            return bool(cnt and cnt > 0)
    except Exception:
        logger.exception('Failed to query running crawl_runs')
        return False


# -----------------------------------------------------------------------------
# Table-swap reconciliation helpers
# -----------------------------------------------------------------------------
async def create_table_like(target_table: str, new_table: str, conn) -> None:
    """Create a new table with the same structure as target_table.

    This uses the PostgreSQL LIKE clause to copy column definitions and
    constraints. Indexes are not copied automatically and will be created
    separately.
    """
    try:
        await conn.execute(f"CREATE TABLE {new_table} (LIKE {target_table} INCLUDING ALL);")
        logger.info(f"Created swap table {new_table} like {target_table}")
    except Exception:
        logger.exception(f"Failed to create table {new_table} like {target_table}")
        raise


async def insert_rows_into_table(records: List[Dict[str, Any]], table_name: str, conn) -> int:
    """Insert a list of normalized CVE records into the specified table.

    Expects each record to have keys: cve_id, published, last_modified, source, data
    Returns the number of rows inserted (best-effort).
    """
    if not records:
        return 0
    batch_size = 200
    inserted = 0
    try:
        for i in range(0, len(records), batch_size):
            batch = records[i:i+batch_size]
            values = [(
                r['cve_id'],
                r.get('published'),
                r.get('last_modified'),
                r.get('source'),
                json.dumps(r.get('data', {}))
            ) for r in batch]
            await conn.executemany(f"""
                INSERT INTO {table_name} (cve_id, published, last_modified, source, data)
                VALUES ($1, $2, $3, $4, $5)
            """, values)
            inserted += len(batch)
        logger.info(f"Inserted {inserted} rows into {table_name}")
    except Exception:
        logger.exception(f"Failed inserting rows into {table_name}")
        raise
    return inserted


async def replicate_indexes_to_table(source_table: str, target_table: str, conn) -> None:
    """Replicate non-primary indexes from source_table to target_table.

    This reads index definitions from pg_indexes and issues equivalent
    CREATE INDEX statements for the new table. It's a pragmatic replication
    strategy; complex index definitions should be reviewed if replication fails.
    """
    try:
        rows = await conn.fetch("SELECT indexdef FROM pg_indexes WHERE tablename = $1", source_table)
        for r in rows:
            idxdef = r['indexdef']
            # replace the source table name with the target table name
            # indexdef commonly looks like: CREATE INDEX name ON public.source_table USING ...
            if source_table in idxdef:
                new_idxdef = idxdef.replace(source_table, target_table)
            else:
                # best-effort fallback
                new_idxdef = idxdef
            # Skip index creations that refer to constraints (primary/unique) already copied
            if 'pkey' in new_idxdef or 'PRIMARY KEY' in new_idxdef:
                continue
            # Execute the index creation; if it fails, log and continue
            try:
                await conn.execute(new_idxdef)
                logger.info(f"Created index on {target_table} from definition: {new_idxdef}")
            except Exception:
                logger.exception(f"Failed to create index on {target_table}: {new_idxdef}")
        logger.info(f"Replicated indexes from {source_table} to {target_table}")
    except Exception:
        logger.exception('Failed to replicate indexes')
        raise


async def atomic_swap_tables(new_table: str, target_table: str, conn) -> None:
    """Atomically swap the new_table into place of target_table.

    Procedure:
      - rename target_table -> target_table_old (if exists)
      - rename new_table -> target_table
      - drop target_table_old

    The renames are executed inside a transaction so the swap is atomic.
    """
    old_table = f"{target_table}_old"
    try:
        # perform quick transactional rename
        await conn.execute('BEGIN')
        # If target doesn't exist, the rename will skip via IF EXISTS logic
        await conn.execute(f"ALTER TABLE IF EXISTS {target_table} RENAME TO {old_table}")
        await conn.execute(f"ALTER TABLE {new_table} RENAME TO {target_table}")
        await conn.execute('COMMIT')
        logger.info(f"Swapped {new_table} into place as {target_table}")
        # drop old table if present (do this outside transaction)
        await conn.execute(f"DROP TABLE IF EXISTS {old_table}")
        logger.info(f"Dropped old table {old_table}")
    except Exception:
        try:
            await conn.execute('ROLLBACK')
        except Exception:
            pass
        logger.exception(f"Failed to atomically swap {new_table} into {target_table}")
        raise



# -----------------------------------------------------------------------------
# Advisory lock helpers
#
# Use Postgres advisory locks to ensure only one writer runs for a named key
# (for example, per-source). Usage:
#
#   async with AdvisoryLock('nvd') as conn:
#       # conn is an asyncpg.Connection with the advisory lock held
#       await conn.execute("-- do upserts here --")
#
# Advisory locks are connection-scoped; the context manager acquires a
# connection from the pool, obtains the advisory lock and releases both
# lock and connection on exit.
# -----------------------------------------------------------------------------


def _advisory_key(name: str) -> int:
    """Deterministically convert a string to a 63-bit signed integer key.

    PostgreSQL advisory lock functions accept BIGINT; we compute a stable
    integer from the SHA-256 of the name and reduce it to the signed
    63-bit range to be safe.
    """
    h = hashlib.sha256(name.encode('utf-8')).digest()[:8]
    val = int.from_bytes(h, 'big')
    return val % (2**63 - 1)


class AdvisoryLock:
    """Async context manager which acquires a Postgres advisory lock.

    On enter it acquires a connection from the pool and attempts to obtain
    the advisory lock. If acquiring the lock fails an exception is raised.

    The yielded object is the acquired asyncpg Connection which may be used
    for transactional writes. On exit the lock is released and the
    connection returned to the pool.
    """

    def __init__(self, name: str):
        self.name = name
        self._conn = None
        self._key = _advisory_key(name)

    async def __aenter__(self) -> Any:
        # Ensure pool exists
        _require_asyncpg()
        if not db_pool.pool:
            await db_pool.initialize()

        # Acquire a dedicated connection for the lock
        self._conn = await db_pool.pool.acquire()

        got = await self._conn.fetchval('SELECT pg_try_advisory_lock($1)', self._key)
        if not got:
            # release connection and raise so caller can decide what to do
            await db_pool.pool.release(self._conn)
            self._conn = None
            raise RuntimeError(f"Could not acquire advisory lock: {self.name}")

        logger.info(f"Advisory lock acquired: {self.name} (key={self._key})")
        return self._conn

    async def __aexit__(self, exc_type, exc, tb):
        if self._conn:
            try:
                await self._conn.execute('SELECT pg_advisory_unlock($1)', self._key)
                logger.info(f"Advisory lock released: {self.name} (key={self._key})")
            except Exception:
                logger.exception("Error releasing advisory lock")
            finally:
                await db_pool.pool.release(self._conn)
                self._conn = None


class AdvisoryXactLock:
    """Transaction-scoped advisory lock.

    This context manager acquires a dedicated connection from the pool,
    starts a transaction, and obtains a transaction-scoped advisory lock
    using `pg_advisory_xact_lock(key)`. The lock is automatically released
    by PostgreSQL when the transaction ends (commit/rollback).

    Usage:
        async with AdvisoryXactLock('nvd') as conn:
            # conn is an asyncpg.Connection inside an open transaction
            await conn.execute("-- perform upserts here --")

    Behavior:
    - Blocks until the advisory lock is available (uses pg_advisory_xact_lock).
    - Starts a transaction on enter and commits on normal exit. If an
      exception occurs inside the context the transaction is rolled back.
    - Because the lock is tied to the transaction, the lock is released
      automatically when the transaction ends.
    """

    def __init__(self, name: str):
        self.name = name
        self._conn = None
        self._key = _advisory_key(name)
        self._txn = None

    async def __aenter__(self) -> Any:
        # Ensure pool exists
        _require_asyncpg()
        if not db_pool.pool:
            await db_pool.initialize()

        # Acquire a dedicated connection for the transaction
        self._conn = await db_pool.pool.acquire()

        # Start a transaction on this connection
        self._txn = self._conn.transaction()
        await self._txn.start()

        # Acquire the transaction-scoped advisory lock (this will block)
        await self._conn.execute('SELECT pg_advisory_xact_lock($1)', self._key)
        logger.info(f"Advisory xact lock acquired: {self.name} (key={self._key})")
        return self._conn

    async def __aexit__(self, exc_type, exc, tb):
        # Commit or rollback the transaction depending on exception
        try:
            if exc_type is None:
                await self._txn.commit()
                logger.info(f"Transaction committed for: {self.name}")
            else:
                await self._txn.rollback()
                logger.info(f"Transaction rolled back for: {self.name} due to exception")
        except Exception:
            logger.exception("Error finishing transaction for AdvisoryXactLock")
        finally:
            if self._conn:
                await db_pool.pool.release(self._conn)
                self._conn = None
