# TIS-API Frontend Guide (Editorial + Public)

This guide covers how to build a rich admin/editor frontend (with inline editing) and a public site against TIS-API. It reflects the current API and fields, including flexible extras, public_extras, and curated_patch overrides.

## Auth, Roles, Network

- Admin endpoints: under `/admin/*`; require Bearer JWT with roles.
  - Roles used: `admin`, `editor`, `reviewer`, `publisher`.
- Public endpoints: under `/public/*`; no auth.
- IP allowlist: `/admin/*` is protected. If you see 403 IP not allowed, add your IP/CIDR to INTERNAL_IP_ALLOWLIST or work from the trusted network.
- Swagger: `/docs` supports “Authorize” for Bearer tokens.

## Data shapes (what you can edit)

Curations (by CVE ID):
- Fields
  - cve_id (string, required)
  - title (string, required)
  - summary (string, optional)
  - body_md (string, optional; Markdown)
  - tags (array of strings, default [])
  - references (array of objects; recommended keys: title, url)
  - curation_status (string: draft|review|published|archived; default draft)
  - source_status (string; free-form, e.g., upstream/original status)
  - status (legacy string; kept for compatibility; set to match curation_status during publish/unpublish)
  - curated_patch (object; JSON Merge Patch to override any raw NVD `data.cve.*` fields)
  - extras (object; editor-only)
  - public_extras (object; exposed publicly)
  - created_by, updated_by, created_at, updated_at, published_at (server-managed)

Alerts (non‑CVE):
- Fields
  - id (uuid; server can generate)
  - slug (string, required, unique)
  - title (string, required)
  - body_md (string, required; Markdown)
  - severity (string: info|medium|high|critical)
  - categories (array of strings, default [])
  # TIS-API Frontend Guide (Editorial + Public)

  This guide shows how to build an admin/editor UI with inline editing and a public site on top of TIS-API. It reflects the latest API: flexible extras/public_extras, curated_patch (JSON Merge Patch) with array support for metrics (v3.x and v4.x), and unified CVSS fields for display and filtering.

  ## Auth, roles, network

  - Admin endpoints: `/admin/*` require Bearer JWT and allowed IP.
    - Roles: `admin`, `editor`, `reviewer`, `publisher`.
  - Public endpoints: `/public/*` require no auth.
  - IP allowlist protects admin; add your IP/CIDR to INTERNAL_IP_ALLOWLIST if you see 403.
  - Swagger `/docs` has “Authorize” for tokens.

  ## Core data models (editable fields)

  ### Curations (per CVE)
  - Fields
    - cve_id: string (primary key)
    - title: string (required)
    - summary: string
    - body_md: string (Markdown)
    - tags: string[] (default [])
    - references: {title, url}[]
  - curation_status: draft|review|published|archived (lowercase; default draft)
    - source_status: string (free-form)
  - status: legacy string, mirrored on publish/unpublish (lowercase)
    - curated_patch: object (JSON Merge Patch to override raw `data.cve.*`)
      - Supports arrays for metrics families: keys like `cvssMetricV31`, `cvssMetricV30`, `cvssMetricV40`, future `cvssMetricV41`, etc.
      - Highest baseScore in an array is chosen for display in public views.
    - extras: object (internal only)
    - public_extras: object (exposed publicly)
    - created_by, updated_by, created_at, updated_at, published_at (server-managed)

  ### Alerts (non‑CVE)
  - Fields
    - id: uuid (server can generate)
    - slug: string (required, unique)
    - title: string (required)
    - body_md: string (required; Markdown)
  - severity: info|medium|high|critical (lowercase)
    - categories: string[]
    - references: {title, url}[]
    - status: draft|review|published|archived
    - extras, public_extras: objects
    - created_by, updated_by, created_at, updated_at, published_at

  Notes
  - public_extras is included in public APIs; extras is internal only.
  - Publication uses curation_status (curations) and status (alerts).

  ## APIs you’ll use

  ### Curations (admin)
  - Upsert: POST `/admin/curations` (admin, editor)
    - Send any subset of editable fields. Server upserts by cve_id.
    - Example (abbrev):
      {
        "cve_id": "CVE-2025-7775",
        "title": "NetScaler memory overflow",
        "curation_status": "review",
        "tags": ["rce","netscaler"],
        "references": [{"title":"Vendor","url":"https://…"}],
        "curated_patch": {
          "cve": {
            "metrics": {
              "cvssMetricV31": [ {"cvssData": {"baseScore": 9.8, "baseSeverity": "CRITICAL"}} ],
              "cvssMetricV40": [ {"cvssData": {"baseScore": 9.2, "baseSeverity": "CRITICAL"}} ]
            }
          }
        },
        "public_extras": {"affected_products":["ADC 13.1","Gateway 14.1"]}
      }
  - Get: GET `/admin/curations/{cve_id}` (all roles)
  - List: GET `/admin/curations?status=&q=&limit=&offset=`
    - status filters COALESCE(curation_status, status)
  - Publish/Unpublish: POST `/admin/curations/{cve_id}/publish` or `/unpublish` (admin, publisher)

  ### Alerts (admin)
  - Create: POST `/admin/alerts` (admin, editor)
  - Update: PUT `/admin/alerts/{id_or_slug}` (admin, editor)
  - Get/List: GET `/admin/alerts/{id_or_slug}`, GET `/admin/alerts?...`
  - Publish/Unpublish: POST `/admin/alerts/{id_or_slug}/publish|unpublish`

  ### Public (read-only)

  Alerts
  - GET `/public/alerts?q=&severity=&category=&limit=&offset=`
    - Returns: id, slug, title, body_md, severity, categories, references, public_extras, published_at
  - GET `/public/alert/{slug}`

  Curated CVEs
  - GET `/public/cves?q=&severity=&has_kev=&tag=&limit=&offset=`
    - Returns: cve_id, curated_title, curated_summary, curated_body_md, tags, references, public_extras, published_at, cve_published,
      cvss_score, cvss_severity, cvss_v40_score, cvss_v40_severity, cvss_v31_score, cvss_v31_severity, is_kev
    - severity filter uses unified cvss_severity (case-insensitive)
  - GET `/public/cve/{cve_id}`

  How unified CVSS works (public):
  - We choose the highest baseScore from curated v4* arrays, else curated v3* arrays.
  - If not curated, we fall back to source metrics (v4.0 → v3.1 → v3.0 → v2).
  - Unified fields: cvss_score, cvss_severity. Versioned fields (v40, v31) remain for detail.

  ## Inline editing patterns (contentEditable-like)

  Goal: edit everything in place with soft validation and autosave.

  Recommended UX
  - Title, summary: contentEditable; save on blur/Enter (Shift+Enter for newline).
  - Body (Markdown):
    - Either contentEditable → sanitize → convert to Markdown on save (Turndown for HTML→MD), or a Markdown editor with live preview.
  - Tags: token chips; save whole array on change.
  - References: dynamic list of {title,url}; add/remove/reorder; validate urls.
  - Statuses: curation_status dropdown; source_status free text.
  - Extras/public_extras:
    - Two tabs: Internal (extras) and Public (public_extras).
    - Provide simple key/value helpers and a JSON editor for nested data.
  - curated_patch (advanced):
    - JSON editor bound to curated_patch using JSON Merge Patch semantics.
    - Only include overrides; omit what you’re not changing. Use null to remove keys.
    - Common overrides:
      - Descriptions: { "cve": { "descriptions": [{"lang":"en","value":"Clarified …"}] } }
      - Metrics (arrays supported):
        { "cve": { "metrics": { "cvssMetricV31": [ {"cvssData": {"baseScore": 9.1, "baseSeverity": "CRITICAL"}} ] } } }
        { "cve": { "metrics": { "cvssMetricV40": [ {"cvssData": {"baseScore": 9.3, "baseSeverity": "CRITICAL"}} ] } } }
    - Public view picks the highest baseScore for display.

  Autosave & concurrency
  - Debounce 600–1000 ms; show Saving/Saved timestamps.
  - Keep a dirty flag; block Publish while dirty.
  - Optionally compare updated_at on save and prompt if the record changed remotely.

  Validation
  - Required: curations need cve_id + title; alerts need slug + title + body_md + severity.
  - URLs must be valid; clamp very long strings; guard JSON size for extras/public_extras.
  - Enforce allowed statuses in the UI.

  ## Publishing flow
  - Curations: Publish sets curation_status=published and refreshes public matview.
  - Alerts: Publish sets status=published and refreshes public matview.
  - Show published_at.

  ## Examples

  Upsert curation (inline save, with metrics arrays)
  {
    "cve_id":"CVE-2025-7775",
    "title":"NetScaler memory overflow",
    "summary":"RCE/DoS in NetScaler ADC/Gateway when …",
    "body_md":"### Impact\n…",
    "tags":["rce","netscaler"],
    "references":[{"title":"Citrix KB","url":"https://support.citrix.com/support-home/kbsearch/article?articleNumber=CTX694938"}],
    "curation_status":"review",
    "curated_patch":{
      "cve":{
        "metrics":{
          "cvssMetricV31":[{"cvssData":{"baseScore":9.8,"baseSeverity":"CRITICAL"}}],
          "cvssMetricV40":[{"cvssData":{"baseScore":9.2,"baseSeverity":"CRITICAL"}}]
        }
      }
    },
    "public_extras":{"affected_products":["ADC 13.1","Gateway 14.1"]}
  }

  Update alert (inline save)
  PUT /admin/alerts/{id_or_slug}
  {
    "title":"Urgent: rotate TLS certs due to OpenSSL bug",
    "body_md":"### Summary\n…",
    "severity":"critical",
    "categories":["openssl","incident"],
    "references":[{"title":"Vendor notice","url":"https://…"}],
    "extras":{"playbook_id":"PB-142"},
    "public_extras":{"actions":["rotate-certs","reboot"]}
  }

  ## Public rendering tips
  - Render body_md as Markdown.
  - Use cvss_score/cvss_severity for badges; keep versioned fields for detail.
  - is_kev highlights KEV entries; show due date/actions if present in public_extras.

  ## Troubleshooting
  - 401: missing/invalid token on admin routes.
  - 403: IP not allowed; adjust INTERNAL_IP_ALLOWLIST or use a trusted network.
  - 404: record not found or not published.
  - 400: validation issues; keep unsaved edits and show inline errors.

  ## Roadmap (optional)
  - ETag/If-Match for safer concurrent edits.
  - Public overrides for description and other fields via curated_patch.
  - History endpoints to surface version snapshots.
  - RSS/Email feeds for public.

  This guide reflects the generalized metrics handling (arrays; v3.x and v4.x), curated overrides, and unified CVSS for a stable frontend.
  - curated_patch supports arrays for `cvssMetricV40` and `cvssMetricV31`; the highest baseScore is chosen for display.
