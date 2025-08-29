-- Redesigned TIS-API Database Schema
-- Clean JSONB-based design for flexibility and performance
-- Created: August 25, 2025

-- =============================================================================
-- 1. NIST / NVD CVE Table
-- =============================================================================
CREATE TABLE nvd_cves (
    cve_id TEXT PRIMARY KEY,          -- CVE-2025-43768, etc.
    published TIMESTAMP NOT NULL,     -- from the JSON "published"
    last_modified TIMESTAMP NOT NULL, -- from the JSON "lastModified"
    source TEXT,                      -- e.g., psirt@fortinet.com
    data JSONB NOT NULL               -- full original JSON document
);

-- Indexes for performance
-- Fast lookup by CVE ID (primary key already does this)
-- Index for filtering by published date (for partition pruning or queries)
CREATE INDEX idx_nvd_published ON nvd_cves (published);

-- JSONB GIN index for flexible queries inside the JSON
CREATE INDEX idx_nvd_data_gin ON nvd_cves USING gin (data jsonb_path_ops);

-- Optional: functional index for frequent queries like baseSeverity
CREATE INDEX idx_nvd_base_severity ON nvd_cves(
    (data #>> '{cve,metrics,cvssMetricV40,0,cvssData,baseSeverity}')
);

-- Additional functional indexes for common CVSS queries
CREATE INDEX idx_nvd_cvss_v31_score ON nvd_cves(
    CAST(data #>> '{cve,metrics,cvssMetricV31,0,cvssData,baseScore}' AS FLOAT)
);

CREATE INDEX idx_nvd_cvss_v30_score ON nvd_cves(
    CAST(data #>> '{cve,metrics,cvssMetricV30,0,cvssData,baseScore}' AS FLOAT)
);

CREATE INDEX idx_nvd_cvss_v2_score ON nvd_cves(
    CAST(data #>> '{cve,metrics,cvssMetricV2,0,cvssData,baseScore}' AS FLOAT)
);

-- =============================================================================
-- 2. CISA KEV Table
-- =============================================================================
CREATE TABLE cisa_kev (
    cve_id TEXT PRIMARY KEY,          -- CVE-YYYY-NNNN
    vendor_project TEXT,              -- extracted if you want quick queries
    product TEXT,                     -- optional
    date_added DATE,                   -- CISA date_added field
    required_action TEXT,              -- extracted if needed
    due_date DATE,                     -- extracted if needed
    data JSONB NOT NULL                -- full original JSON document
);

-- Indexes for CISA KEV
CREATE INDEX idx_cisa_date_added ON cisa_kev (date_added);
CREATE INDEX idx_cisa_data_gin ON cisa_kev USING gin (data jsonb_path_ops);
CREATE INDEX idx_cisa_vendor_project ON cisa_kev (vendor_project);
CREATE INDEX idx_cisa_due_date ON cisa_kev (due_date);

-- =============================================================================
-- 3. Optional: Materialized View for Quick CVE Overview
-- =============================================================================
-- This view combines data from both tables and extracts commonly accessed fields
CREATE MATERIALIZED VIEW cve_overview AS
-- NVD rows (joined to CISA when available)
SELECT 
    n.cve_id,
    n.published,
    n.last_modified,
    n.source,
    CASE WHEN k.cve_id IS NOT NULL THEN 'both' ELSE 'nvd' END as table_source,
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
WHERE NOT EXISTS (SELECT 1 FROM nvd_cves n2 WHERE n2.cve_id = k.cve_id);

-- Index on the materialized view for fast queries
CREATE INDEX idx_cve_overview_cve_id ON cve_overview (cve_id);
CREATE INDEX idx_cve_overview_published ON cve_overview (published);
CREATE INDEX idx_cve_overview_cvss_scores ON cve_overview (cvss_v40_score, cvss_v31_score, cvss_v30_score, cvss_v2_score);
CREATE INDEX idx_cve_overview_is_kev ON cve_overview (is_kev);

-- =============================================================================
-- 4. Functions for Common Operations
-- =============================================================================

-- Function to get the primary CVSS score for a CVE (preferring newer versions)
CREATE OR REPLACE FUNCTION get_primary_cvss_score(cve_data JSONB)
RETURNS TABLE (
    version TEXT,
    score FLOAT,
    severity TEXT,
    vector TEXT
) AS $$
BEGIN
    -- Try CVSS v4.0 first
    IF cve_data #> '{cve,metrics,cvssMetricV40,0}' IS NOT NULL THEN
        RETURN QUERY SELECT 
            '4.0'::TEXT,
            CAST(cve_data #>> '{cve,metrics,cvssMetricV40,0,cvssData,baseScore}' AS FLOAT),
            cve_data #>> '{cve,metrics,cvssMetricV40,0,cvssData,baseSeverity}',
            cve_data #>> '{cve,metrics,cvssMetricV40,0,cvssData,vectorString}';
        RETURN;
    END IF;
    
    -- Try CVSS v3.1
    IF cve_data #> '{cve,metrics,cvssMetricV31,0}' IS NOT NULL THEN
        RETURN QUERY SELECT 
            '3.1'::TEXT,
            CAST(cve_data #>> '{cve,metrics,cvssMetricV31,0,cvssData,baseScore}' AS FLOAT),
            cve_data #>> '{cve,metrics,cvssMetricV31,0,cvssData,baseSeverity}',
            cve_data #>> '{cve,metrics,cvssMetricV31,0,cvssData,vectorString}';
        RETURN;
    END IF;
    
    -- Try CVSS v3.0
    IF cve_data #> '{cve,metrics,cvssMetricV30,0}' IS NOT NULL THEN
        RETURN QUERY SELECT 
            '3.0'::TEXT,
            CAST(cve_data #>> '{cve,metrics,cvssMetricV30,0,cvssData,baseScore}' AS FLOAT),
            cve_data #>> '{cve,metrics,cvssMetricV30,0,cvssData,baseSeverity}',
            cve_data #>> '{cve,metrics,cvssMetricV30,0,cvssData,vectorString}';
        RETURN;
    END IF;
    
    -- Try CVSS v2.0
    IF cve_data #> '{cve,metrics,cvssMetricV2,0}' IS NOT NULL THEN
        RETURN QUERY SELECT 
            '2.0'::TEXT,
            CAST(cve_data #>> '{cve,metrics,cvssMetricV2,0,cvssData,baseScore}' AS FLOAT),
            NULL::TEXT, -- v2.0 doesn't have severity
            cve_data #>> '{cve,metrics,cvssMetricV2,0,cvssData,vectorString}';
        RETURN;
    END IF;
    
    -- No CVSS data found
    RETURN;
END;
$$ LANGUAGE plpgsql IMMUTABLE;

-- =============================================================================
-- 5. Refresh function for materialized view
-- =============================================================================
CREATE OR REPLACE FUNCTION refresh_cve_overview()
RETURNS void AS $$
BEGIN
    REFRESH MATERIALIZED VIEW CONCURRENTLY cve_overview;
END;
$$ LANGUAGE plpgsql;
