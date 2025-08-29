-- Migration: create unique index on cve_overview to allow CONCURRENTLY refresh
-- Created: 2025-08-26

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_class c
        JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relname = 'cve_overview' AND n.nspname = 'public'
    ) THEN
        RAISE NOTICE 'Materialized view cve_overview does not exist; skipping index creation';
        RETURN;
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_indexes WHERE tablename = 'cve_overview' AND indexname = 'ux_cve_overview_cve_id'
    ) THEN
        EXECUTE 'CREATE UNIQUE INDEX CONCURRENTLY ux_cve_overview_cve_id ON cve_overview (cve_id)';
        RAISE NOTICE 'Created unique index ux_cve_overview_cve_id';
    ELSE
        RAISE NOTICE 'Unique index ux_cve_overview_cve_id already exists';
    END IF;
END$$;
