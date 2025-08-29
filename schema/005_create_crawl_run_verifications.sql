-- Create a table to record verification outcomes comparing first_total vs actual DB count
CREATE TABLE IF NOT EXISTS crawl_run_verifications (
    id SERIAL PRIMARY KEY,
    run_id TEXT NOT NULL,
    first_total INTEGER NULL,
    db_count INTEGER NULL,
    ok BOOLEAN NOT NULL,
    note TEXT NULL,
    checked_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_crawl_run_verifications_run_id ON crawl_run_verifications (run_id);
