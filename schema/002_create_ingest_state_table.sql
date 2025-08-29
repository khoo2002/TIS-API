-- Create tables to track ingest state and materialized view refresh time
CREATE TABLE IF NOT EXISTS ingest_state (
    source TEXT PRIMARY KEY,
    last_changed TIMESTAMPTZ DEFAULT NULL,
    last_stored_count INTEGER DEFAULT 0,
    last_run TIMESTAMPTZ DEFAULT NULL
);

CREATE TABLE IF NOT EXISTS refresh_state (
    name TEXT PRIMARY KEY,
    last_refreshed TIMESTAMPTZ DEFAULT NULL
);

-- Seed a row for the cve_overview refresh tracking
INSERT INTO refresh_state (name, last_refreshed)
VALUES ('cve_overview', NULL)
ON CONFLICT (name) DO NOTHING;
