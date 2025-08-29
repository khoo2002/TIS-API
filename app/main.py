"""
Simplified FastAPI application for CVE data
JSONB-based design for maximum flexibility
"""
from fastapi import FastAPI, HTTPException, Query, Depends
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from typing import Optional, List, Dict, Any
from datetime import datetime, date, timedelta
import logging
import asyncio
import os
import ipaddress

from .database import (
    db_pool, 
    get_nvd_cve, 
    search_cves, 
    get_database_stats,
    refresh_materialized_view,
    ensure_cve_overview_structure,
    get_last_successful_finish_at,
    get_last_attempt_at,
    get_fetch_log,
    ensure_one_time_jobs_table,
    create_one_time_job,
    get_due_one_time_jobs,
    mark_job_started,
    mark_job_finished
)
from .database import get_cve_overview_total
# additional imports
from .database import get_all_ingest_state, get_refresh_state
from .database import is_source_running
from .database import cleanup_duplicates
from .database import get_scheduler_flag, set_scheduler_flag, get_scheduler_flag_row
# attempt to import scheduler controls; optional if scheduler not running in this process
try:
    from ingest import scheduler as ingest_scheduler
except Exception:
    ingest_scheduler = None
# Import runner to allow programmatic ingestion trigger
from ingest.runner import run_source
import asyncio
import httpx

from .auth import require_auth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(
    title="TIS-API Redesigned",
    description="Threat Intelligence System API with JSONB-based CVE storage",
    version="2.0.0"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# =============================================================================
# Internal IP allowlist (for non-public endpoints like /admin)
# Configure with env:
#   INTERNAL_PROTECTED_PREFIXES: comma-separated list of path prefixes (default: "/admin")
#   INTERNAL_IP_ALLOWLIST: comma-separated IPv4/IPv6 addresses or CIDR ranges (empty=allow all)
#   INTERNAL_TRUST_FORWARD_HEADERS: "true" to use X-Forwarded-For/X-Real-IP when behind proxy
# =============================================================================

_protected_prefixes = [p.strip() for p in os.getenv('INTERNAL_PROTECTED_PREFIXES', '/admin').split(',') if p.strip()]
_trust_forward = os.getenv('INTERNAL_TRUST_FORWARD_HEADERS', 'false').lower() in ('1', 'true', 't', 'yes', 'y')

_allowlist_raw = [t.strip() for t in os.getenv('INTERNAL_IP_ALLOWLIST', '').split(',') if t.strip()]
_allowlist_networks: List[ipaddress._BaseNetwork] = []
for token in _allowlist_raw:
    try:
        # Interpret plain IPs as /32 (IPv4) or /128 (IPv6)
        net = ipaddress.ip_network(token, strict=False)
        _allowlist_networks.append(net)
    except Exception:
        logger.warning("Skipping invalid allowlist entry: %s", token)


def _client_ip_from_headers(scope_headers: Dict[str, str]) -> Optional[str]:
    # Prefer X-Forwarded-For first hop if trusted
    if _trust_forward:
        xff = scope_headers.get('x-forwarded-for')
        if xff:
            # Take the first IP in the list
            first = xff.split(',')[0].strip()
            if first:
                return first
        xri = scope_headers.get('x-real-ip')
        if xri:
            return xri.strip()
    return None


@app.middleware("http")
async def internal_ip_allowlist(request, call_next):
    try:
        path = request.url.path or "/"
        protected = any(path.startswith(pref) for pref in _protected_prefixes)
        if not protected:
            return await call_next(request)

        # If no allowlist configured, allow all IPs for convenience
        if not _allowlist_networks:
            return await call_next(request)

        # Build lowercase header map
        headers_map = {k.decode('latin-1').lower(): v.decode('latin-1') for k, v in request.scope.get('headers', [])}

        ip_str = _client_ip_from_headers(headers_map) or (request.client.host if request.client else None)
        if not ip_str:
            # No client IP, deny
            return JSONResponse(status_code=403, content={"detail": "IP not allowed"})

        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            logger.warning("Malformed client IP: %s", ip_str)
            return JSONResponse(status_code=403, content={"detail": "IP not allowed"})

        allowed = any(ip_obj in net for net in _allowlist_networks)
        if not allowed:
            logger.info("Blocked IP %s for path %s", ip_str, path)
            return JSONResponse(status_code=403, content={"detail": "IP not allowed"})

        return await call_next(request)
    except Exception:
        logger.exception("IP allowlist middleware error")
        return JSONResponse(status_code=500, content={"detail": "Internal server error"})

# =============================================================================
# Startup and Shutdown Events
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Initialize database connection pool"""
    try:
        await db_pool.initialize()
        # Do not block startup: schedule ensure+refresh in background
        async def _post_start_tasks():
            # small delay to avoid competing with healthcheck
            await asyncio.sleep(3)
            try:
                logger.info("Ensuring cve_overview structure (background)...")
                await ensure_cve_overview_structure()
            except Exception:
                logger.exception('Background ensure_cve_overview_structure failed')
            # try a refresh a bit later; retry lightly if DB is busy
            for i, delay in enumerate((5, 15, 30), start=1):
                try:
                    ok = await refresh_materialized_view()
                    if ok:
                        logger.info("Background refresh completed on attempt %d", i)
                        break
                except Exception:
                    logger.exception('Background refresh attempt %d failed', i)
                await asyncio.sleep(delay)
        try:
            asyncio.get_event_loop().create_task(_post_start_tasks())
        except RuntimeError:
            # In rare cases event loop retrieval fails; fall back to immediate run with shield
            await asyncio.shield(_post_start_tasks())

        # Start a lightweight scheduler loop to execute one-time jobs
        async def _one_time_job_runner():
            try:
                await ensure_one_time_jobs_table()
            except Exception:
                logger.exception('Failed to ensure one_time_jobs table at startup')
            while True:
                try:
                    jobs = await get_due_one_time_jobs(limit=5)
                    for job in jobs:
                        jid = str(job['id']) if isinstance(job['id'], (str,)) else str(job['id'])
                        # attempt to mark as running (avoid double-exec)
                        started = await mark_job_started(jid)
                        if not started:
                            continue
                        ok = False
                        err = None
                        try:
                            src = job.get('source')
                            # reuse existing runner
                            await run_source(src)
                            ok = True
                        except Exception as ex:
                            logger.exception('Error running one-time job %s', jid)
                            err = str(ex)[:800]
                        finally:
                            try:
                                await mark_job_finished(jid, ok, error=err)
                            except Exception:
                                logger.exception('Failed to mark job %s finished', jid)
                except Exception:
                    logger.exception('One-time job runner loop error')
                await asyncio.sleep(10)

        try:
            asyncio.get_event_loop().create_task(_one_time_job_runner())
        except RuntimeError:
            pass
        logger.info("TIS-API startup complete (non-blocking ensure scheduled)")
    except Exception as e:
        logger.error(f"Startup failed: {e}")
        # Don't raise on startup failure, just log it
        # This allows the health endpoint to work even if DB is down

@app.on_event("shutdown")
async def shutdown_event():
    """Clean up database connections"""
    try:
        await db_pool.close()
        logger.info("TIS-API shutdown complete")
    except Exception as e:
        logger.error(f"Shutdown error: {e}")

# =============================================================================
# API Endpoints
# =============================================================================

@app.get("/")
async def root():
    """Root endpoint with API information"""
    return {
        "name": "TIS-API Redesigned",
        "version": "2.0.0",
        "description": "Threat Intelligence System with JSONB-based CVE storage",
        "endpoints": {
            "cve_by_id": "/cve/{cve_id}",
            "search_cves": "/cves/search",
            "database_stats": "/stats",
            "health": "/health"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    try:
        stats = await get_database_stats()
        return {
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat(),
            "database": "connected",
            "cve_count": stats.get('nvd_cves_total', 0)
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        raise HTTPException(status_code=503, detail="Service unavailable")

@app.get("/cve/{cve_id}")
async def get_cve_by_id(cve_id: str) -> Dict[str, Any]:
    """
    Get a specific CVE by its ID
    
    Args:
        cve_id: CVE identifier (e.g., CVE-2025-12345)
    
    Returns:
        Full CVE data including JSONB fields
    """
    # Validate CVE ID format
    if not cve_id.upper().startswith('CVE-'):
        raise HTTPException(
            status_code=400, 
            detail="Invalid CVE ID format. Expected: CVE-YYYY-NNNNN"
        )
    
    try:
        cve = await get_nvd_cve(cve_id.upper())
        if not cve:
            raise HTTPException(status_code=404, detail="CVE not found")
        
        return cve
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving CVE {cve_id}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/cves/search")
async def search_cves_endpoint(
    q: Optional[str] = Query(None, description="Search term in description or CVE ID (partial ok)"),
    min_score: Optional[float] = Query(None, ge=0.0, le=10.0, description="Minimum CVSS score (any version)"),
    max_score: Optional[float] = Query(None, ge=0.0, le=10.0, description="Maximum CVSS score (any version)"),
    severity: Optional[str] = Query(None, pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$", description="Single CVSS severity"),
    severity_in: Optional[List[str]] = Query(None, description="List of severities to include (LOW,MEDIUM,HIGH,CRITICAL)"),
    has_kev: Optional[bool] = Query(None, description="Only CISA KEV if true; exclude if false"),
    date_from: Optional[date] = Query(None, description="Published date from (YYYY-MM-DD)"),
    date_to: Optional[date] = Query(None, description="Published date to (YYYY-MM-DD)"),
    last_modified_from: Optional[date] = Query(None, description="Last modified from (YYYY-MM-DD)"),
    last_modified_to: Optional[date] = Query(None, description="Last modified to (YYYY-MM-DD)"),
    sources: Optional[List[str]] = Query(None, description="Filter by sources (nvd,cisa) membership"),
    cve_id: Optional[str] = Query(None, description="Exact CVE ID (e.g., CVE-2025-12345)"),
    cve_id_contains: Optional[str] = Query(None, description="Partial CVE ID match"),
    sort_by: Optional[str] = Query(None, description="Sort by: published,last_modified,cvss_v40_score,cvss_v31_score,cvss_v30_score,cvss_v2_score,kev_date_added,is_kev,cve_id"),
    sort_dir: Optional[str] = Query(None, description="asc or desc"),
    limit: int = Query(50, ge=1, le=1000, description="Maximum results to return"),
    offset: int = Query(0, ge=0, description="Results offset for pagination")
) -> Dict[str, Any]:
    """
    Search CVEs with flexible filtering
    
    Returns:
        Paginated search results with metadata
    """
    try:
        # Convert date objects to datetime for database query
        date_from_dt = datetime.combine(date_from, datetime.min.time()) if date_from else None
        date_to_dt = datetime.combine(date_to, datetime.max.time()) if date_to else None
        lm_from_dt = datetime.combine(last_modified_from, datetime.min.time()) if last_modified_from else None
        lm_to_dt = datetime.combine(last_modified_to, datetime.max.time()) if last_modified_to else None
        
        # Validate score range
        if min_score is not None and max_score is not None and min_score > max_score:
            raise HTTPException(
                status_code=400,
                detail="min_score cannot be greater than max_score"
            )
        
        results = await search_cves(
            query=q,
            min_score=min_score,
            max_score=max_score,
            severity=severity,
            severity_in=severity_in,
            has_kev=has_kev,
            date_from=date_from_dt,
            date_to=date_to_dt,
            last_modified_from=lm_from_dt,
            last_modified_to=lm_to_dt,
            sources=sources,
            cve_id=cve_id,
            cve_id_contains=cve_id_contains,
            sort_by=sort_by,
            sort_dir=sort_dir,
            limit=limit,
            offset=offset
        )
        
        # Add pagination metadata
        results['pagination'] = {
            'has_more': offset + len(results['cves']) < results['total_count'],
            'next_offset': offset + limit if offset + len(results['cves']) < results['total_count'] else None
        }
        
        # Add filters applied for debugging
        results['filters_applied'] = {
            'query': q,
            'min_score': min_score,
            'max_score': max_score,
            'severity': severity,
            'severity_in': severity_in,
            'has_kev': has_kev,
            'date_from': str(date_from) if date_from else None,
            'date_to': str(date_to) if date_to else None,
            'last_modified_from': str(last_modified_from) if last_modified_from else None,
            'last_modified_to': str(last_modified_to) if last_modified_to else None,
            'sources': sources,
            'cve_id': cve_id,
            'cve_id_contains': cve_id_contains,
            'sort_by': sort_by,
            'sort_dir': sort_dir
        }
        
        return results
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error searching CVEs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/stats")
async def get_stats() -> Dict[str, Any]:
    """
    Get database statistics and metrics
    
    Returns:
        Various statistics about the CVE database
    """
    try:
        return await get_database_stats()
    except Exception as e:
        logger.error(f"Error getting stats: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/admin/refresh-view")
async def refresh_view(claims = Depends(require_auth(['admin']))):
    """
    Administrative endpoint to refresh the materialized view
    
    Returns:
        Success status
    """
    try:
        success = await refresh_materialized_view()
        if not success:
            # light retry once after a short wait
            await asyncio.sleep(2)
            success = await refresh_materialized_view()
        if success:
            return {"status": "success", "message": "Materialized view refreshed"}
        raise HTTPException(status_code=500, detail="Failed to refresh view")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error refreshing view: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")


@app.post("/admin/trigger-ingest")
async def trigger_ingest(source: str = None, max_cves: int = None, claims = Depends(require_auth(['admin']))):
    """Trigger ingestion for a source (nvd|cisa) or both if omitted.

    This endpoint schedules the ingest job in the background and returns
    immediately with an accepted response. Use /admin/refresh-view to force
    a synchronous refresh of the materialized view if desired.
    """
    # validate source
    if source and source not in (None, 'nvd', 'cisa'):
        raise HTTPException(status_code=400, detail="source must be 'nvd' or 'cisa'")

    # schedule background task
    loop = asyncio.get_event_loop()

    async def _run():
        if source:
            await run_source(source, max_items=max_cves)
        else:
            await run_source('nvd', max_items=max_cves)
            await run_source('cisa')

    loop.create_task(_run())
    return {"status": "accepted", "message": "Ingest scheduled"}


@app.get('/admin/ingest-status')
async def ingest_status(claims = Depends(require_auth(['admin']))):
    """Return ingest state and last refresh info for cve_overview"""
    try:
        ingest = await get_all_ingest_state()
        refresh = await get_refresh_state('cve_overview')
        return {'ingest_state': ingest, 'refresh_state': refresh}
    except Exception as e:
        logger.exception('Error getting ingest status')
        raise HTTPException(status_code=500, detail='Failed to get ingest status')


@app.get('/admin/ingest/status/{source}')
async def get_source_status(source: str, claims = Depends(require_auth(['admin']))):
    """Return 'running' or 'rest' for the given source (nvd|cisa)."""
    if source not in ('nvd', 'cisa'):
        raise HTTPException(status_code=400, detail="source must be 'nvd' or 'cisa'")
    try:
        running = await is_source_running(source)
        state = 'running' if running else 'rest'
        return {'source': source, 'status': state}
    except Exception:
        logger.exception('Failed to get source status')
        raise HTTPException(status_code=500, detail='Failed to get source status')


@app.get('/admin/ingest/status')
async def get_all_sources_status(claims = Depends(require_auth(['admin']))):
    """Return a summary status for both sources."""
    try:
        nvd_running = await is_source_running('nvd')
        cisa_running = await is_source_running('cisa')
        return {
            'nvd': 'running' if nvd_running else 'rest',
            'cisa': 'running' if cisa_running else 'rest'
        }
    except Exception:
        logger.exception('Failed to get aggregate source status')
        raise HTTPException(status_code=500, detail='Failed to get aggregate source status')


@app.get('/admin/crawl-jobs')
async def crawl_jobs(limit: int = 10, claims = Depends(require_auth(['admin']))):
    """Return the latest `limit` persisted crawl runs ordered by started_at desc.

    Default limit is 10. This returns data from the `crawl_runs` table.
    """
    try:
        from .database import get_recent_crawl_runs
        limit = max(1, min(limit, 100))
        rows = await get_recent_crawl_runs(limit=limit)
        return {'status': 'success', 'crawl_jobs': rows}
    except Exception as e:
        logger.exception('Error getting crawl jobs')
        raise HTTPException(status_code=500, detail='Failed to get crawl jobs')


@app.get('/admin/last-crawl')
async def last_crawl(claims = Depends(require_auth(['admin']))):
    """Return the latest crawl times per source and the last materialized view refresh time.

    This provides a concise view for users to know "data up to" timestamps.
    """
    try:
        ingest = await get_all_ingest_state()
        refresh = await get_refresh_state('cve_overview')

        # Build a compact mapping of source -> last_run/last_changed metadata
        sources = {}
        for s in ingest:
            sources[s.get('source')] = {
                'last_changed': s.get('last_changed'),
                'last_stored_count': s.get('last_stored_count'),
                'last_run': s.get('last_run')
            }

        result = {
            'sources': sources,
            'materialized_view': refresh
        }
        return {'status': 'success', 'last_crawl': result}
    except Exception as e:
        logger.exception('Error getting last crawl info')
        raise HTTPException(status_code=500, detail='Failed to get last crawl info')


# -----------------------------------------------------------------------------
# New endpoints: logs per source, staleness, and one-time scheduling
# -----------------------------------------------------------------------------

@app.get('/admin/fetch-log')
async def fetch_log(source: Optional[str] = None, limit: int = Query(10, ge=1, le=100), claims = Depends(require_auth(['admin']))):
    try:
        logs = await get_fetch_log(source=source, limit=limit)
        return {'status': 'success', 'logs': logs}
    except Exception:
        logger.exception('Failed to get fetch log')
        raise HTTPException(status_code=500, detail='Failed to get fetch log')


@app.get('/admin/staleness')
async def staleness(claims = Depends(require_auth(['admin']))):
    """Return how long the data hasn't updated for each source and the view.

    Computes durations since last successful finished_at per source and last_refreshed for the matview.
    """
    try:
        now = datetime.utcnow()
        out = {}
        for src in ('nvd', 'cisa'):
            last_ok = await get_last_successful_finish_at(src)
            last_attempt = await get_last_attempt_at(src)
            src_info = {
                'last_success': last_ok.isoformat() if last_ok else None,
                'last_attempt': last_attempt,
                'age_success_seconds': (now - last_ok).total_seconds() if last_ok else None,
            }
            out[src] = src_info
        # matview
        refresh = await get_refresh_state('cve_overview')
        if refresh and refresh.get('last_refreshed'):
            try:
                # parse ISO string back to datetime in UTC-safe way
                last_ref = datetime.fromisoformat(refresh['last_refreshed'].replace('Z', '+00:00'))
            except Exception:
                last_ref = None
        else:
            last_ref = None
        out['cve_overview'] = {
            'last_refreshed': refresh.get('last_refreshed') if refresh else None,
            'age_seconds': (now - last_ref).total_seconds() if last_ref else None,
        }
        return {'status': 'success', 'staleness': out}
    except Exception:
        logger.exception('Failed to compute staleness')
        raise HTTPException(status_code=500, detail='Failed to compute staleness')


@app.post('/admin/schedule-once')
async def schedule_once(source: str, run_at: Optional[datetime] = None, params: Optional[Dict[str, Any]] = None, claims = Depends(require_auth(['admin']))):
    """Schedule a one-time crawl for a source (nvd|cisa). If run_at is omitted, runs ASAP.

    Returns the job id and status.
    """
    if source not in ('nvd', 'cisa'):
        raise HTTPException(status_code=400, detail="source must be 'nvd' or 'cisa'")
    try:
        when = run_at or datetime.utcnow()
        job = await create_one_time_job(source, when, params or {})
        return {'status': 'scheduled', 'job': job}
    except Exception:
        logger.exception('Failed to schedule one-time job')
        raise HTTPException(status_code=500, detail='Failed to schedule job')


@app.post('/admin/cleanup-duplicates')
async def cleanup_duplicates_endpoint(claims = Depends(require_auth(['admin']))):
    """Admin endpoint to find and remove duplicate rows across all public tables.

    Returns a report per table with counts of duplicate groups and rows removed.
    """
    try:
        report = await cleanup_duplicates()
        return {'status': 'success', 'report': report}
    except Exception as e:
        logger.exception('Error running cleanup_duplicates')
        raise HTTPException(status_code=500, detail='Cleanup failed')


# -----------------------------------------------------------------------------
# Real-time NVD totalResults check
# -----------------------------------------------------------------------------
@app.get('/admin/nvd/total')
async def nvd_total_results(claims = Depends(require_auth(['admin']))):
    """
    Query NVD's /cves/2.0 endpoint to return the current totalResults reported by NVD.

    Returns:
        JSON: { "totalResults": <int>, "fetched_at": <iso-ts> }
    """
    nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    # Use a short timeout to avoid hanging the API
    timeout = httpx.Timeout(10.0, connect=5.0)

    headers = {
        "User-Agent": "TIS-API/2.0 (nvd-total-check)"
    }

    async with httpx.AsyncClient(timeout=timeout) as client:
        try:
            resp = await client.get(nvd_url, headers=headers, params={"resultsPerPage": 1})
        except httpx.RequestError as e:
            logger.exception(f"Error contacting NVD: {e}")
            raise HTTPException(status_code=502, detail="Failed to contact NVD")

    if resp.status_code != 200:
        logger.error(f"NVD returned {resp.status_code}: {resp.text}")
        raise HTTPException(status_code=502, detail=f"NVD returned {resp.status_code}")

    try:
        body = resp.json()
        # NVD uses top-level `totalResults` field per their API docs
        total = body.get('totalResults')
        if total is None:
            # Some responses may nest metadata differently; try common alternatives
            total = body.get('results', {}).get('totalResults') if isinstance(body.get('results'), dict) else None

        if total is None:
            logger.error(f"Unable to parse totalResults from NVD response: {body}")
            raise HTTPException(status_code=502, detail="Unexpected NVD response format")

        return {"totalResults": int(total), "fetched_at": datetime.utcnow().isoformat()}

    except ValueError:
        logger.exception("Failed to decode NVD JSON response")
        raise HTTPException(status_code=502, detail="Invalid JSON from NVD")

# =============================================================================
# Advanced Query Endpoints
# =============================================================================

@app.get("/cves/by-severity/{severity}")
async def get_cves_by_severity(
    severity: str,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
) -> Dict[str, Any]:
    """
    Get CVEs filtered by severity level
    
    Args:
        severity: CVSS severity (LOW, MEDIUM, HIGH, CRITICAL)
    
    Returns:
        CVEs matching the severity level
    """
    if severity.upper() not in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        raise HTTPException(
            status_code=400,
            detail="Severity must be one of: LOW, MEDIUM, HIGH, CRITICAL"
        )
    
    try:
        return await search_cves(
            severity=severity.upper(),
            limit=limit,
            offset=offset
        )
    except Exception as e:
        logger.error(f"Error getting CVEs by severity {severity}: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get("/cves/kev")
async def get_kev_cves(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
) -> Dict[str, Any]:
    """
    Get all CVEs that are in CISA's Known Exploited Vulnerabilities catalog
    
    Returns:
        CVEs marked as KEV
    """
    try:
        return await search_cves(
            has_kev=True,
            limit=limit,
            offset=offset
        )
    except Exception as e:
        logger.error(f"Error getting KEV CVEs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

@app.get('/admin/nvd/full-round')
async def nvd_full_round_status(claims = Depends(require_auth(['admin']))):
    """Return whether the scheduled NVD full-round job is enabled."""
    try:
        row = await get_scheduler_flag_row('nvd_full_round_enabled')
        if not row:
            # default enabled
            return {'nvd_full_round_enabled': True, 'raw_flag': None, 'audit': None}
        enabled = True if row['value'] is None else (row['value'].lower() in ('1', 'true', 't', 'yes', 'y'))
        return {
            'nvd_full_round_enabled': enabled,
            'raw_flag': row['value'],
            'audit': {
                'updated_at': row.get('updated_at'),
                'updated_by': row.get('updated_by'),
                'updated_reason': row.get('updated_reason')
            }
        }
    except Exception:
        logger.exception('Failed to read nvd_full_round flag')
        raise HTTPException(status_code=500, detail='Failed to read flag')

@app.post('/admin/nvd/full-round/activate')
async def nvd_full_round_activate(updated_by: Optional[str] = None, reason: Optional[str] = None, claims = Depends(require_auth(['admin']))):
    """Activate the scheduled NVD full-round job. Accepts optional audit fields: updated_by, reason."""
    try:
        ok = await set_scheduler_flag('nvd_full_round_enabled', 'true', updated_by=updated_by, updated_reason=reason)
        if not ok:
            raise HTTPException(status_code=500, detail='Failed to set flag')

        # If scheduler is running in this process, resume the job immediately
        try:
            if ingest_scheduler and hasattr(ingest_scheduler, 'resume_nvd_full_round_job'):
                await ingest_scheduler.resume_nvd_full_round_job()
        except Exception:
            logger.exception('Failed to resume nvd_full_round job after activate')

        row = await get_scheduler_flag_row('nvd_full_round_enabled')
        return {'status': 'success', 'nvd_full_round_enabled': True, 'audit': row}
    except HTTPException:
        raise
    except Exception:
        logger.exception('Failed to activate nvd full round')
        raise HTTPException(status_code=500, detail='Failed to activate')

@app.post('/admin/nvd/full-round/deactivate')
async def nvd_full_round_deactivate(updated_by: Optional[str] = None, reason: Optional[str] = None, claims = Depends(require_auth(['admin']))):
    """Deactivate the scheduled NVD full-round job. Accepts optional audit fields: updated_by, reason."""
    try:
        ok = await set_scheduler_flag('nvd_full_round_enabled', 'false', updated_by=updated_by, updated_reason=reason)
        if not ok:
            raise HTTPException(status_code=500, detail='Failed to set flag')

        # If scheduler is running in this process, pause the job immediately
        try:
            if ingest_scheduler and hasattr(ingest_scheduler, 'pause_nvd_full_round_job'):
                await ingest_scheduler.pause_nvd_full_round_job()
        except Exception:
            logger.exception('Failed to pause nvd_full_round job after deactivate')

        row = await get_scheduler_flag_row('nvd_full_round_enabled')
        return {'status': 'success', 'nvd_full_round_enabled': False, 'audit': row}
    except HTTPException:
        raise
    except Exception:
        logger.exception('Failed to deactivate nvd full round')
        raise HTTPException(status_code=500, detail='Failed to deactivate')


@app.post('/admin/nvd/full-round/run')
async def nvd_full_round_run_now(max_cves: Optional[int] = None, claims = Depends(require_auth(['admin']))):
    """Schedule an immediate, ad-hoc full-round paginated NVD crawl with safe swap reconciliation.

    This runs in the background and returns immediately with an accepted response.
    Optionally provide `max_cves` to limit the number of CVEs fetched for testing.
    """
    try:
        loop = asyncio.get_event_loop()

        async def _run():
            try:
                await run_source('nvd', full_round=True, refresh_on_finish=True, max_items=max_cves)
            except Exception:
                logger.exception('Error running ad-hoc nvd full-round')

        loop.create_task(_run())
        return {'status': 'accepted', 'message': 'NVD full-round run scheduled'}
    except Exception:
        logger.exception('Failed to schedule NVD full-round run')
        raise HTTPException(status_code=500, detail='Failed to schedule run')

@app.get("/cves/recent")
async def get_recent_cves(
    days: int = Query(7, ge=1, le=365, description="Number of days back to search"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0)
) -> Dict[str, Any]:
    """
    Get recently published CVEs
    
    Args:
        days: Number of days back to search (default: 7)
    
    Returns:
        Recently published CVEs
    """
    try:
        # Use a timedelta to compute the date_from safely
        date_from = datetime.utcnow() - timedelta(days=days)
        results = await search_cves(
            date_from=date_from,
            limit=limit,
            offset=offset
        )

        # Build pagination metadata
        total = int(results.get('total_count', 0))
        returned = len(results.get('cves', []))
        has_more = (offset + returned) < total
        next_offset = offset + limit if has_more else None
        prev_offset = offset - limit if offset - limit >= 0 else (0 if offset > 0 else None)
        total_pages = (total + limit - 1) // limit if limit > 0 else 1
        current_page = (offset // limit) + 1 if limit > 0 else 1

        total_overall = await get_cve_overview_total()

        return {
            'status': 'success',
            'recent': results.get('cves', []),
            'total_count': total,
            'total_overview': total_overall,
            'limit': limit,
            'offset': offset,
            'pagination': {
                'has_more': has_more,
                'next_offset': next_offset,
                'prev_offset': prev_offset,
                'page': current_page,
                'total_pages': total_pages
            }
        }
    except Exception as e:
        logger.error(f"Error getting recent CVEs: {e}")
        raise HTTPException(status_code=500, detail="Internal server error")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
