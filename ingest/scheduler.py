import asyncio
import logging
from datetime import datetime, timedelta
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.executors.asyncio import AsyncIOExecutor
from apscheduler.triggers.interval import IntervalTrigger
from .adapters.nvd import NVDAdapter
from .adapters.cisa import CISAAdapter
from .runner import run_source
from .logger import StructuredLogger
from app.database import get_recent_crawl_runs, get_scheduler_flag, get_last_successful_finish_at
from app.database import ensure_cve_overview_structure
from app.database import db_pool

logger = logging.getLogger(__name__)

import os

# Intervals may be tuned via environment variables. Defaults are intentionally
# small to allow frequent incremental checks; tune in production.
NVD_INTERVAL_SECONDS = max(int(os.getenv('NVD_INTERVAL_SECONDS', '60')), 60)
CISA_INTERVAL_SECONDS = int(os.getenv('CISA_INTERVAL_SECONDS', '60'))
NVD_FULL_ROUND_HOURS = int(os.getenv('NVD_FULL_ROUND_HOURS', '6'))
NVD_INCREMENTAL_WINDOW_MINUTES = int(os.getenv('NVD_INCREMENTAL_WINDOW_MINUTES', '60'))
NVD_INCREMENTAL_MAX_ITEMS = int(os.getenv('NVD_INCREMENTAL_MAX_ITEMS', '4000'))

SOURCES = {
    'nvd': {'adapter': NVDAdapter, 'interval_seconds': NVD_INTERVAL_SECONDS},
    'cisa': {'adapter': CISAAdapter, 'interval_seconds': CISA_INTERVAL_SECONDS},
}


# Module-level scheduler reference so other modules (e.g., app.main) can
# pause/resume jobs at runtime.
scheduler = None


def start_scheduler():
    StructuredLogger.configure()
    StructuredLogger.start_run()
    global scheduler
    # Use dedicated executors so NVD and CISA don't block each other
    executors = {
        'default': AsyncIOExecutor(),
        'nvd': AsyncIOExecutor(),
        'cisa': AsyncIOExecutor(),
    }
    job_defaults = {
        'coalesce': True,       # if runs are missed, run only once
        'max_instances': 1,     # per-job guard; we configure per job where needed
        'misfire_grace_time': 30,
    }
    scheduler = AsyncIOScheduler(executors=executors, job_defaults=job_defaults)

    # Ensure the database pool is initialized before any scheduled job runs,
    # so helpers like get_last_successful_finish_at() can obtain a connection
    # without raising "Database pool not initialized" on first run.
    try:
        loop = asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(db_pool.initialize())
    except Exception:
        logger.exception('Failed to pre-initialize database pool; scheduled jobs will attempt lazy init later')

    # Only schedule non-NVD sources here (NVD has dedicated incremental and full-round jobs)
    for name, cfg in SOURCES.items():
        if name == 'nvd':
            continue  # Skip generic NVD job - handled by dedicated incremental and full-round jobs
            
        # Ensure interval is at least 1s unless explicitly configured lower
        interval = max(1, int(cfg.get('interval_seconds', 60)))
        trigger = IntervalTrigger(seconds=interval)

        async def _job(source_name: str):
            try:
                # For non-NVD sources, use the last successful finished_at as the since window
                since_dt = None
                until_dt = None
                try:
                    # Get raw datetime from DB to avoid string parsing issues
                    since_dt = await get_last_successful_finish_at(source_name)
                except Exception:
                    logging.exception('Failed to read last successful finished_at for %s', source_name)
                    since_dt = None

                # Set a small overlap window to ensure no misses (e.g., 2 minutes)
                if since_dt:
                    since_dt = since_dt - timedelta(minutes=2)

                await run_source(source_name, since=since_dt, until=until_dt)
            except Exception:
                logging.exception('Error running scheduled source %s', source_name)

        # Schedule the coroutine job directly; run immediately and then every interval
        scheduler.add_job(
            _job,
            trigger,
            args=[name],
            id=name,
            name=name,
            replace_existing=True,
            next_run_time=datetime.utcnow(),
            max_instances=1,
            executor='cisa' if name == 'cisa' else 'default',
        )

    scheduler.start()
    logger.info('Scheduler started with sources: %s', list(SOURCES.keys()))

    # Kick off a one-time, non-blocking ensure of the matview structure shortly after start
    try:
        scheduler.add_job(ensure_cve_overview_structure, 'date', run_date=datetime.utcnow(), id='ensure_mv_once', replace_existing=True)
    except Exception:
        logger.exception('Failed to schedule one-time ensure_cve_overview_structure job')

    # Schedule NVD incremental job: runs frequently (e.g., every minute) and fetches changes within the last window
    async def _nvd_incremental():
        try:
            now = datetime.utcnow()
            since = now - timedelta(minutes=NVD_INCREMENTAL_WINDOW_MINUTES)
            until = now
            # incremental mode: non-destructive, no reconciliation delete
            await run_source('nvd', since=since, until=until, full_round=False, refresh_on_finish=False, max_items=NVD_INCREMENTAL_MAX_ITEMS)
        except Exception:
            logging.exception('Error running NVD incremental job')

    # Stagger NVD incremental slightly to avoid simultaneous starts with other per-minute jobs
    scheduler.add_job(
        _nvd_incremental,
        IntervalTrigger(seconds=NVD_INTERVAL_SECONDS),
        id='nvd_incremental',
        name='nvd_incremental',
        replace_existing=True,
        # stagger the first run slightly to avoid colliding exactly with other per-minute jobs
        next_run_time=(datetime.utcnow() + timedelta(seconds=10)),
        # keep single instance and run on its own executor
        max_instances=1,
        executor='nvd'
    )

    # Schedule NVD full-round job: runs every N hours, crawls entire dataset (paginated) and performs reconciliation at end
    async def _nvd_full_round():
        try:
            now = datetime.utcnow()
            since = None
            until = now
            # Check runtime flag to see if full-round runs are enabled
            try:
                flag = await get_scheduler_flag('nvd_full_round_enabled')
            except Exception:
                logging.exception('Failed to read nvd_full_round_enabled flag; defaulting to enabled')
                flag = None

            enabled = True if flag is None else (flag.lower() in ('1', 'true', 't', 'yes', 'y'))
            if not enabled:
                logger.info('NVD full-round job is disabled via scheduler flag; skipping this run')
                return

            await run_source('nvd', since=since, until=until, full_round=True, refresh_on_finish=True)
        except Exception:
            logging.exception('Error running NVD full round job')

    scheduler.add_job(_nvd_full_round, IntervalTrigger(hours=NVD_FULL_ROUND_HOURS), id='nvd_full_round', name='nvd_full_round', replace_existing=True, next_run_time=datetime.utcnow(), max_instances=1)

    # Schedule a daily full reconciliation job (runs once per day at UTC 03:00)
    async def _daily_full_reconcile():
        try:
            # For NVD we'll request the maximum allowed 120-day window to catch changes
            now = datetime.utcnow()
            since = now - timedelta(days=120)
            await run_source('nvd', since=since, until=now)
        except Exception:
            logging.exception('Error during daily full reconciliation')

    # Schedule at 03:00 UTC daily
    scheduler.add_job(_daily_full_reconcile, 'cron', hour=3, minute=0, id='daily_full_reconcile', replace_existing=True, max_instances=1)

    try:
        asyncio.get_event_loop().run_forever()
    except (KeyboardInterrupt, SystemExit):
        logger.info('Scheduler stopping')
    scheduler.shutdown()


if __name__ == '__main__':
    # When executed as a module (python -m ingest.scheduler) start the
    # scheduler. This is intentionally top-level so the container CMD can
    # execute the scheduler module directly.
    start_scheduler()


async def pause_nvd_full_round_job():
    """Pause the scheduled NVD full-round job if the scheduler is running."""
    global scheduler
    if scheduler is None:
        logger.warning('Scheduler not running; cannot pause nvd_full_round')
        return False
    try:
        job = scheduler.get_job('nvd_full_round')
        if not job:
            logger.warning('nvd_full_round job not found to pause')
            return False
        job.pause()
        logger.info('nvd_full_round job paused')
        return True
    except Exception:
        logger.exception('Failed to pause nvd_full_round job')
        return False


async def resume_nvd_full_round_job():
    """Resume the scheduled NVD full-round job if the scheduler is running."""
    global scheduler
    if scheduler is None:
        logger.warning('Scheduler not running; cannot resume nvd_full_round')
        return False
    try:
        job = scheduler.get_job('nvd_full_round')
        if not job:
            logger.warning('nvd_full_round job not found to resume')
            return False
        job.resume()
        logger.info('nvd_full_round job resumed')
        return True
    except Exception:
        logger.exception('Failed to resume nvd_full_round job')
        return False
