import asyncio
import os
import argparse
import logging
import json
from typing import Optional, List
from .adapters.nvd import NVDAdapter
from .adapters.cisa import CISAAdapter
from .lock import PgAdvisoryLock
from .logger import StructuredLogger

# Import refresh helper
from app.database import refresh_materialized_view
from app.database import db_pool
from app.database import record_crawl_run_start, record_crawl_run_finish, record_crawl_run_set_first_total
import asyncpg

logging.getLogger().setLevel(logging.INFO)
logger = logging.getLogger(__name__)


async def run_source(adapter_name: str, max_items: Optional[int] = None, since=None, until=None, start_index: Optional[int] = None, full_round: bool = False, refresh_on_finish: bool = True):
    if adapter_name == 'nvd':
        adapter = NVDAdapter()
    elif adapter_name == 'cisa':
        adapter = CISAAdapter()
    else:
        raise ValueError('Unknown adapter')

    logger.info('Starting run for %s', adapter_name)

    async with adapter:
        # Acquire advisory lock per source to prevent concurrent runs
        async with PgAdvisoryLock(adapter_name) as conn:
            # Start a persisted run record
            run_id = StructuredLogger.start_run()
            try:
                await record_crawl_run_start(run_id, adapter_name)
            except Exception:
                logger.exception('Failed to persist crawl run start')

            try:
                # Special handling for NVD: the API provides pagination metadata
                if adapter_name == 'nvd':
                    # Allow manual init from a provided start_index (useful to resume or re-crawl from offset)
                    start = int(start_index) if start_index is not None else 0
                    per_page = 2000 if not max_items else min(2000, max_items)
                    total_reported = None
                    total_stored = 0
                    first_run = True
                    fetched_ids = []  # keep order for batching inserts

                    async def _fetch_with_retries(start_index, results_per_page, attempts=3, since_param=None, until_param=None):
                        delay = 1
                        for attempt in range(1, attempts + 1):
                            try:
                                return await adapter.fetch(start_index=start_index, results_per_page=results_per_page, since=since_param, until=until_param)
                            except Exception:
                                logger.exception('Fetch attempt %s failed for start=%s', attempt, start_index)
                                if attempt == attempts:
                                    raise
                                await asyncio.sleep(delay)
                                delay *= 2

                    # Determine NVD rate limits: 50 requests/30s with API key, 5 requests/30s without
                    api_key = os.getenv('NVD_API_KEY') or getattr(adapter, 'api_key', None)
                    if api_key:
                        allowed_per_30s = 50
                    else:
                        allowed_per_30s = 5
                    sleep_interval = 30.0 / float(allowed_per_30s)

                    # If caller provided a since/until date window, pass it through to the adapter
                    since_param = since
                    until_param = until

                    while True:
                        raw = await _fetch_with_retries(start, per_page, since_param=since_param, until_param=until_param)
                        if not raw:
                            break
                        if first_run:
                            total_reported = int(raw.get('totalResults') or 0)
                            first_run = False
                            first_run_total = total_reported
                            logger.info('NVD totalResults reported: %s', total_reported)
                            # persist the first page's totalResults so later verification can compare
                            try:
                                await record_crawl_run_set_first_total(run_id, first_run_total)
                            except Exception:
                                logger.exception('Failed to persist first_run_total for crawl run')

                        records = await adapter.normalize(raw)
                        # collect ids for reconciliation
                        for r in records:
                            fetched_ids.append(r['cve_id'])

                        if max_items:
                            # respect global max_items across pages
                            remaining = max_items - total_stored
                            if remaining <= 0:
                                break
                            records = records[:remaining]

                        stored = await adapter.store(records, conn=conn)
                        total_stored += stored
                        logger.info('Stored %s records for nvd (running total: %s)', stored, total_stored)

                        # Throttle to respect NVD rate limits (sleep between requests)
                        try:
                            await asyncio.sleep(sleep_interval)
                        except asyncio.CancelledError:
                            raise

                        # Advance paging
                        start += len(raw.get('vulnerabilities', []))
                        # Stop if we've reached the end or hit max_items
                        if start >= (total_reported or 0):
                            break
                        if max_items and total_stored >= max_items:
                            break

                    # Post-ingest verification: either destructive reconciliation for full rounds
                    # or a simple DB count check for incremental runs.
                    db_count = None
                    if full_round:
                        try:
                            # Use table-swap reconciliation to avoid long-running DELETE locks.
                            # Steps:
                            # 1) create a new table like nvd_cves: nvd_cves_swap_<run_id>
                            # 2) insert normalized records into the swap table
                            # 3) replicate indexes from nvd_cves to swap table
                            # 4) atomically rename swap table into place under the advisory lock
                            swap_table = f"nvd_cves_swap_{run_id.replace('-', '_')}"
                            logger.info('Creating swap table %s', swap_table)
                            await conn.execute(f"CREATE TABLE IF NOT EXISTS {swap_table} (LIKE nvd_cves INCLUDING ALL)")

                            # Insert current fetched records into swap table using batches
                            # We need the normalized records - re-fetch in chunks from adapter or use fetched_ids mapping
                            # For simplicity and to avoid a second normalize pass here, use adapter.store to insert into the swap table.
                            # adapter.store currently writes to nvd_cves; we'll perform direct inserts using normalization output.
                            # Rewind through the fetched IDs and fetch full records from adapter.normalize; but keeping memory reasonable.
                            # Here we assume `records` variable contains last page; therefore we will re-run a streaming pass to re-normalize all pages.
                            inserted_total = 0
                            start2 = 0
                            per_page2 = 2000
                            first_pass = True
                            while True:
                                raw2 = await adapter.fetch(start_index=start2, results_per_page=per_page2, since=since_param, until=until_param)
                                if not raw2:
                                    break
                                norm = await adapter.normalize(raw2)
                                # Insert normalized rows into swap table in batches
                                batch_size = 200
                                tuples = [(
                                    r['cve_id'],
                                    r.get('published'),
                                    r.get('last_modified'),
                                    r.get('source'),
                                    json.dumps(r.get('data', {}))
                                ) for r in norm]
                                for i in range(0, len(tuples), batch_size):
                                    chunk = tuples[i:i+batch_size]
                                    await conn.executemany(f"INSERT INTO {swap_table} (cve_id, published, last_modified, source, data) VALUES ($1, $2, $3, $4, $5)", chunk)
                                    inserted_total += len(chunk)
                                # advance
                                start2 += len(raw2.get('vulnerabilities', []))
                                if start2 >= (total_reported or 0):
                                    break

                            logger.info('Inserted %s rows into swap table %s', inserted_total, swap_table)

                            # replicate indexes from nvd_cves to swap table
                            try:
                                from app.database import replicate_indexes_to_table
                                await replicate_indexes_to_table('nvd_cves', swap_table, conn)
                            except Exception:
                                logger.exception('Failed to replicate indexes to swap table')

                            # Now perform an atomic swap using a pool connection under advisory lock
                            try:
                                async with db_pool.get_connection() as outer_conn:
                                    from app.database import atomic_swap_tables
                                    await atomic_swap_tables(swap_table, 'nvd_cves', outer_conn)
                            except Exception:
                                logger.exception('Failed to perform atomic swap of swap table into nvd_cves')

                            # fetch final db_count
                            db_count = await conn.fetchval('SELECT COUNT(*) FROM nvd_cves')
                        except Exception:
                            logger.exception('Failed to reconcile nvd_cves with swap table')
                            # fallback: try to get db_count via pool
                            try:
                                async with db_pool.get_connection() as check_conn:
                                    db_count = await check_conn.fetchval('SELECT COUNT(*) FROM nvd_cves')
                            except Exception:
                                logger.exception('Failed to fetch nvd_cves count for verification')
                                db_count = None
                    else:
                        # incremental non-destructive run: just fetch db_count for comparison
                        try:
                            db_count = await conn.fetchval('SELECT COUNT(*) FROM nvd_cves')
                        except Exception:
                            logger.exception('Failed to fetch nvd_cves count for incremental run')
                            db_count = None

                    logger.info('NVD reported total=%s, stored total this run=%s, db_count=%s', total_reported, total_stored, db_count)

                    # For full rounds, try a reingest if DB has fewer rows than reported total
                    if full_round and total_reported is not None and db_count is not None and db_count < total_reported:
                        logger.warning('DB count (%s) less than NVD totalResults (%s) — attempting reingest to recover missing rows', db_count, total_reported)
                        # simple reingest pass without deleting existing rows
                        start = 0
                        total_added = 0
                        first_run = True
                        while True:
                            raw = await _fetch_with_retries(start, 2000)
                            if not raw:
                                break
                            if first_run:
                                total_reported = int(raw.get('totalResults') or 0)
                                first_run = False
                            records = await adapter.normalize(raw)
                            # store will upsert duplicates safely
                            added = await adapter.store(records, conn=conn)
                            total_added += added
                            start += len(raw.get('vulnerabilities', []))
                            if start >= (total_reported or 0):
                                break
                        logger.info('Reingest pass complete, added approx %s rows', total_added)

                    # Defer refresh: if any changes were stored, schedule a delayed refresh
                    if total_stored and total_stored > 0:
                        async def _delayed_refresh(delay_seconds: int = 30):
                            try:
                                await asyncio.sleep(delay_seconds)
                                await refresh_materialized_view()
                            except Exception:
                                logger.exception('Delayed refresh failed')
                        # Fire-and-forget so we don't block the scheduler job
                        try:
                            asyncio.create_task(_delayed_refresh())
                        except RuntimeError:
                            # If no running loop (unlikely here), fallback to direct await
                            await _delayed_refresh()

                    # record finish success
                    try:
                        await record_crawl_run_finish(run_id, 'success', stored_count=total_stored)
                    except Exception:
                        logger.exception('Failed to persist crawl run finish')
                    # Run verification comparing first_total vs db_count for full rounds
                    try:
                        from app.database import verify_crawl_run_counts
                        verified = await verify_crawl_run_counts(run_id)
                        if not verified:
                            logger.warning('Verification failed: first_total does not match DB count for run %s', run_id)
                        else:
                            logger.info('Verification OK for run %s', run_id)
                    except Exception:
                        logger.exception('Failed to run post-run verification')
                    return total_stored

                else:
                    # For non-NVD sources (like CISA), pass since/until to fetch and normalize
                    raw = await adapter.fetch(since=since, until=until)
                    records = await adapter.normalize(raw, since=since, until=until)
                    if max_items:
                        records = records[:max_items]
                    stored = await adapter.store(records, conn=conn)
                    logger.info('Stored %s records for %s', stored, adapter_name)
                    try:
                        await record_crawl_run_finish(run_id, 'success', stored_count=stored)
                    except Exception:
                        logger.exception('Failed to persist crawl run finish')
                    # Defer refresh if any changes were stored
                    if stored and stored > 0:
                        async def _delayed_refresh(delay_seconds: int = 30):
                            try:
                                await asyncio.sleep(delay_seconds)
                                await refresh_materialized_view()
                            except Exception:
                                logger.exception('Delayed refresh failed')
                        try:
                            asyncio.create_task(_delayed_refresh())
                        except RuntimeError:
                            await _delayed_refresh()
                    return stored

            except Exception as e:
                # record failure
                try:
                    await record_crawl_run_finish(run_id, 'failed', stored_count=0, error=str(e))
                except Exception:
                    logger.exception('Failed to persist crawl run failure')
                raise


async def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=str, help='Source to run (nvd|cisa)')
    parser.add_argument('--max-items', type=int, help='Maximum items to store')
    parser.add_argument('--start-index', type=int, help='Start index for NVD pagination (useful to init or resume)')
    parser.add_argument('--once', action='store_true', help='Run once and exit')
    args = parser.parse_args()

    StructuredLogger.configure()
    run_id = StructuredLogger.start_run()

    if args.source:
        stored = await run_source(args.source, max_items=args.max_items, start_index=args.start_index)
        # If changes occurred, wait 30s then refresh before exit (one-shot/CLI case)
        if stored and stored > 0:
            await asyncio.sleep(30)
            await refresh_materialized_view()
    else:
        # default: run both and refresh only if either stored rows
        total = 0
        s = await run_source('nvd', max_items=args.max_items, start_index=args.start_index)
        total += s or 0
        s2 = await run_source('cisa', max_items=args.max_items)
        total += s2 or 0
        if total > 0:
            await asyncio.sleep(30)
            await refresh_materialized_view()

if __name__ == '__main__':
    asyncio.run(main())
