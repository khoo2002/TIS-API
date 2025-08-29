-- Create crawl_runs table to persist ingestion run history
CREATE TABLE IF NOT EXISTS crawl_runs (
    run_id TEXT PRIMARY KEY,
    source TEXT NOT NULL,
    started_at TIMESTAMP NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMP NULL,
    status TEXT NOT NULL,
    stored_count INTEGER DEFAULT 0,
    error TEXT NULL
);

CREATE INDEX IF NOT EXISTS idx_crawl_runs_source ON crawl_runs (source);
CREATE INDEX IF NOT EXISTS idx_crawl_runs_started_at ON crawl_runs (started_at DESC);
