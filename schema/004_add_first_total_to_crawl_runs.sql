-- Add first_total column to crawl_runs to persist the first page's totalResults for full-round runs
ALTER TABLE IF EXISTS crawl_runs
ADD COLUMN IF NOT EXISTS first_total INTEGER NULL;

-- Optional index to quickly query by first_total if needed
CREATE INDEX IF NOT EXISTS idx_crawl_runs_first_total ON crawl_runs (first_total);
