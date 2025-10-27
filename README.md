# TIS-API (JSONB + Materialized View)
<!-- Video: place Threat-Intel-api.mp4 at the repo root or `docs/` -->
<a href="./Threat-Intel-api.mp4">Threat-Intel-api.mp4</a>
<video controls src="./Threat-Intel-api.mp4" title="Threat-Intel-api" style="max-width:100%;height:auto;">
  Your browser does not support the video tag. Download the video here:
  <a href="./Threat-Intel-api.mp4">Threat-Intel-api.mp4</a>
</video>
A FastAPI service that ingests CVE data from multiple sources (NVD, CISA KEV) into PostgreSQL using a JSONB-first schema. A materialized view `cve_overview` provides a unified, query-friendly surface for fast search.

Highlights
- Robust ingestion with smart upserts and persisted run metadata
- Union materialized view `cve_overview` combining NVD and CISA into one place
- Startup self-heal: containers ensure `cve_overview` structure, indexes, and refresh helper exist
- Advanced, frontend-friendly search via `/cves/search` against `cve_overview`

## Quick start

- Requirements: Docker + Docker Compose
- Bring the stack up (Postgres, API, ingest-worker) without OpenSearch for faster startup:
  - docker-compose --profile "" up -d
  - To include OpenSearch and Dashboards later, add the profile:
    - docker-compose --profile search up -d opensearch dashboards
  - Windows PowerShell: `docker-compose up -d`
- API is at http://localhost:8000
- OpenAPI docs at http://localhost:8000/docs

Health
- API health: `GET /health`
- Basic stats: `GET /stats`

## Data model: cve_overview (materialized view)

The materialized view `cve_overview` is the main read surface:
- Source union:
  - NVD CVEs (optionally joined to CISA when present)
  - CISA-only CVEs (appear when a KEV CVE has no NVD row)
- Key columns:
  - `cve_id` (unique, indexed)
  - `published`, `last_modified`
  - `table_source`: 'nvd' | 'cisa' | 'both' (compat)
  - `table_sources`: text[] array of contributing sources, e.g., ['nvd'], ['cisa'], or ['nvd','cisa']
  - `cvss_v40_score`, `cvss_v31_score`, `cvss_v30_score`, `cvss_v2_score`
  - `description`
  - `is_kev`, `kev_date_added`, `kev_required_action`, `kev_due_date`
- Indexes:
  - Unique on `cve_id` (required for concurrent refresh)
  - Secondary on `published`, score composites, `is_kev`, and GIN on `table_sources`

Startup guarantee
- On container start, the service verifies/builds `cve_overview` with the union + `table_sources` structure and indexes.
- The helper function `refresh_cve_overview()` is ensured for safe concurrent refreshes.

Refresh behavior
- After a successful ingest that changes rows (`stored_count > 0`), a delayed refresh is triggered (~30s) to update `cve_overview`.

## API overview

- `GET /` — API info
- `GET /health` — quick health
- `GET /stats` — DB counts and recent activity
- `GET /cve/{cve_id}` — return a CVE from NVD (raw JSONB included)
- `GET /cves/search` — advanced search over `cve_overview`
- Admin
  - `POST /admin/refresh-view` — force a refresh
  - `POST /admin/trigger-ingest` — trigger ingestion (nvd/cisa)
  - `GET /admin/ingest-status`, `GET /admin/last-crawl`, etc.

## Advanced Search: GET /cves/search

Searches `cve_overview` and returns a paginated result set. All params are optional.

Parameters
- Text and CVE ID
  - `q`: search in `description` or `cve_id` (case-insensitive)
  - `cve_id`: exact CVE ID (e.g., CVE-2025-12345)
  - `cve_id_contains`: partial CVE ID match
- Scores (across 4.0/3.1/3.0/2.0)
  - `min_score`, `max_score`: float (0–10)
- Severity
  - `severity`: one of LOW | MEDIUM | HIGH | CRITICAL
  - `severity_in`: list of severities (repeat query param): `...&severity_in=HIGH&severity_in=CRITICAL`
- CISA KEV
  - `has_kev`: boolean — only KEV if true; exclude KEV if false
- Time windows
  - `date_from`, `date_to`: YYYY-MM-DD — filter by `published`
  - `last_modified_from`, `last_modified_to`: YYYY-MM-DD — filter by `last_modified`
- Sources (union membership)
  - `sources`: list — filter by `table_sources` membership (any-of)
    - Values: `nvd`, `cisa`
    - Example: `...&sources=nvd` (includes overlaps)
    - Example: `...&sources=cisa`
- Sorting (whitelisted)
  - `sort_by`: one of `published`, `last_modified`, `cvss_v40_score`, `cvss_v31_score`, `cvss_v30_score`, `cvss_v2_score`, `kev_date_added`, `is_kev`, `cve_id`
  - `sort_dir`: `asc` or `desc` (default is newest first)
- Pagination
  - `limit`: 1–1000 (default 50), `offset`: default 0

Response
```
{
  "cves": [ { /* row from cve_overview */ }, ... ],
  "total_count": 123,
  "limit": 50,
  "offset": 0,
  "pagination": { "has_more": true, "next_offset": 50 },
  "filters_applied": { /* echo of filters */ }
}
```

Examples (Windows-friendly URLs)
- Text + min score, newest first:
  - `GET http://localhost:8000/cves/search?q=router&min_score=7.5&sort_by=last_modified&sort_dir=desc&limit=25`
- Exact CVE:
  - `GET http://localhost:8000/cves/search?cve_id=CVE-2025-12345`
- High or Critical KEV changed in last 30 days:
  - `GET http://localhost:8000/cves/search?has_kev=true&severity_in=HIGH&severity_in=CRITICAL&last_modified_from=2025-07-28&sort_by=last_modified&sort_dir=desc`
- Filter by source membership (includes overlaps):
  - NVD present: `GET http://localhost:8000/cves/search?sources=nvd`
  - CISA present: `GET http://localhost:8000/cves/search?sources=cisa`
- Published date range:
  - `GET http://localhost:8000/cves/search?date_from=2025-01-01&date_to=2025-06-30`

How to send list params
- Repeat params in the query string:
  - `...?severity_in=HIGH&severity_in=CRITICAL&sources=nvd&sources=cisa`
- With popular clients (requests/httpx): send arrays as values:
  - `params={"sources": ["nvd","cisa"], "severity_in": ["HIGH","CRITICAL"]}`

## Operational notes

- Ingestion runs continuously (per-minute incremental for NVD; periodic full-round; CISA incremental).
- After data changes, the system waits ~30s then refreshes `cve_overview`.
- Manually refresh via `POST /admin/refresh-view`.

## Troubleshooting

- `cve_overview` missing columns or refresh errors:
  - Restart API or ingest containers; startup code ensures structure and indexes.
- Slow queries:
  - Ensure indexes exist: unique on `cve_id`, plus on `published`, score composites, `is_kev`, and a GIN on `table_sources`.
- CISA-only rows are zero:
  - That can be normal if every KEV also exists in NVD currently.

## Extensibility

- Add new sources by writing their JSONB table and extending the matview union; include them in `table_sources`.
- Add filters by adding columns to the view and whitelisting them in search (sorting and where clauses).

If you need exact-only or overlap-only filters (e.g., `sources_mode=only|any|all`), ping me and I’ll wire it without breaking current clients.
