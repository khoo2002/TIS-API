-- Migration: Safely replace cve_overview materialized view with UNION that includes CISA-only rows
-- Safe procedure (zero-downtime approach):
-- 1) Create a new materialized view `cve_overview_new` WITH NO DATA
-- 2) Create the required UNIQUE index (CONCURRENTLY) on `cve_overview_new` (needed for CONCURRENT refresh)
-- 3) Create other indexes CONCURRENTLY (optional but recommended)
-- 4) REFRESH MATERIALIZED VIEW CONCURRENTLY cve_overview_new
-- 5) In a short transactional step, rename the old view out of the way and rename the new view to `cve_overview`
-- 6) (Optional) Recreate any privileges and drop the old view after verification
--
-- IMPORTANT:
-- - This file contains commands that must be run in psql (not inside a transaction block for CONCURRENTLY operations).
-- - Run this from the repo root (or copy into psql). Example (from PowerShell):
--     Get-Content .\schema\003_replace_cve_overview_with_union.sql -Raw | docker-compose exec -T postgres psql -U cveuser -d cvedb
-- - Back up the DB before running: docker-compose exec -T postgres pg_dump -U cveuser -d cvedb > cvedb-before.matview.sql
-- - Creating indexes CONCURRENTLY and REFRESH CONCURRENTLY may take time depending on DB size.
--
-- Note: CREATE INDEX CONCURRENTLY and REFRESH MATERIALIZED VIEW CONCURRENTLY cannot run inside a transaction block.
-- Make sure your psql execution does not wrap the entire file inside a transaction.

-- 1) Create the new materialized view with NO DATA so we can create indexes before populating
CREATE MATERIALIZED VIEW IF NOT EXISTS cve_overview_new AS
-- NVD rows (joined to CISA when available)
SELECT 
    n.cve_id,
    n.published,
    n.last_modified,
    n.source,
    'nvd' as table_source,
    CAST(n.data #>> '{cve,metrics,cvssMetricV40,0,cvssData,baseScore}' AS FLOAT) as cvss_v40_score,
    n.data #>> '{cve,metrics,cvssMetricV40,0,cvssData,baseSeverity}' as cvss_v40_severity,
    CAST(n.data #>> '{cve,metrics,cvssMetricV31,0,cvssData,baseScore}' AS FLOAT) as cvss_v31_score,
    n.data #>> '{cve,metrics,cvssMetricV31,0,cvssData,baseSeverity}' as cvss_v31_severity,
    CAST(n.data #>> '{cve,metrics,cvssMetricV30,0,cvssData,baseScore}' AS FLOAT) as cvss_v30_score,
    n.data #>> '{cve,metrics,cvssMetricV30,0,cvssData,baseSeverity}' as cvss_v30_severity,
    CAST(n.data #>> '{cve,metrics,cvssMetricV2,0,cvssData,baseScore}' AS FLOAT) as cvss_v2_score,
    n.data #>> '{cve,descriptions,0,value}' as description,
    CASE WHEN k.cve_id IS NOT NULL THEN true ELSE false END as is_kev,
    k.date_added as kev_date_added,
    k.required_action as kev_required_action,
    k.due_date as kev_due_date
FROM nvd_cves n
LEFT JOIN cisa_kev k ON n.cve_id = k.cve_id

UNION ALL

-- CISA-only rows (not present in nvd_cves)
SELECT
    k.cve_id,
    k.date_added::timestamp as published,
    k.date_added::timestamp as last_modified,
    NULL as source,
    'cisa' as table_source,
    NULL::FLOAT as cvss_v40_score,
    NULL::TEXT as cvss_v40_severity,
    NULL::FLOAT as cvss_v31_score,
    NULL::TEXT as cvss_v31_severity,
    NULL::FLOAT as cvss_v30_score,
    NULL::TEXT as cvss_v30_severity,
    NULL::FLOAT as cvss_v2_score,
    k.data::text as description,
    true as is_kev,
    k.date_added as kev_date_added,
    k.required_action as kev_required_action,
    k.due_date as kev_due_date
FROM cisa_kev k
WHERE NOT EXISTS (SELECT 1 FROM nvd_cves n2 WHERE n2.cve_id = k.cve_id)
WITH NO DATA;

-- 2) Create the required UNIQUE index (CONCURRENTLY) on cve_overview_new
--     (required for REFRESH MATERIALIZED VIEW CONCURRENTLY to work)
-- Create indexes (non-concurrent) so they can be created on an empty materialized view
CREATE UNIQUE INDEX IF NOT EXISTS ux_cve_overview_new_cve_id ON cve_overview_new (cve_id);
CREATE INDEX IF NOT EXISTS idx_cve_overview_new_published ON cve_overview_new (published);
CREATE INDEX IF NOT EXISTS idx_cve_overview_new_cvss_scores ON cve_overview_new (cvss_v40_score, cvss_v31_score, cvss_v30_score, cvss_v2_score);
CREATE INDEX IF NOT EXISTS idx_cve_overview_new_is_kev ON cve_overview_new (is_kev);

-- 4) Populate the new materialized view with a concurrent refresh
REFRESH MATERIALIZED VIEW CONCURRENTLY cve_overview_new;

-- 5) Swap views atomically using a PL/pgSQL block that renames the old view with a timestamp suffix
DO $$
DECLARE
    ts text := to_char(now(), 'YYYYMMDDHH24MISS');
BEGIN
    -- If an old backup exists, rename it with a timestamp suffix
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'cve_overview_old') THEN
        EXECUTE format('ALTER MATERIALIZED VIEW cve_overview_old RENAME TO cve_overview_old_%s', ts);
    END IF;

    -- If current cve_overview exists, rename it to cve_overview_old
    IF EXISTS (SELECT 1 FROM pg_matviews WHERE matviewname = 'cve_overview') THEN
        EXECUTE 'ALTER MATERIALIZED VIEW cve_overview RENAME TO cve_overview_old';
    END IF;

    -- Rename the new view into place
    EXECUTE 'ALTER MATERIALIZED VIEW cve_overview_new RENAME TO cve_overview';
END; $$;

-- 6) Verification queries you can run after the swap to ensure row counts and a sample match expectations
-- Row counts
-- SELECT 'new_count' as label, COUNT(*) FROM cve_overview;
-- SELECT 'old_count' as label, COUNT(*) FROM cve_overview_old;

-- Sample difference (rows present in old but not in new)
-- SELECT o.cve_id FROM cve_overview_old o LEFT JOIN cve_overview n ON o.cve_id = n.cve_id WHERE n.cve_id IS NULL LIMIT 20;

-- After verification, drop the old view and its indexes
-- DROP MATERIALIZED VIEW IF EXISTS cve_overview_old;

-- 6) (Optional) After verification, drop the old view and its indexes
-- DROP MATERIALIZED VIEW IF EXISTS cve_overview_old_...;

-- Notes:
-- - The `ALTER MATERIALIZED VIEW ... RENAME TO cve_overview_old_$(date +%s)` uses a shell substitution placeholder; when running via psql you should pick a concrete name or run the RENAME step interactively.
-- - Because `CREATE INDEX CONCURRENTLY` and `REFRESH MATERIALIZED VIEW CONCURRENTLY` cannot run inside a transaction block, run this file directly with psql as shown at the top.
-- - If your environment requires more controlled migration, I can split these steps into separate SQL files (create+indexes, refresh, swap) to be executed manually.
