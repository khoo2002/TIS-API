import asyncio
import logging
from datetime import datetime, timezone, timedelta
from ingest.adapters.nvd import NVDAdapter

logging.basicConfig(level=logging.DEBUG)

async def main():
    adapter = NVDAdapter()
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    until = datetime.now(timezone.utc)
    print('Calling NVD with since=%s until=%s' % (since.isoformat(), until.isoformat()))
    res = await adapter.fetch(start_index=0, results_per_page=10, since=since, until=until)
    if res is None:
        print('FETCH_DONE None response')
    else:
        print('FETCH_DONE', res.get('totalResults'), len(res.get('vulnerabilities', [])))

if __name__ == '__main__':
    asyncio.run(main())
import asyncio
import logging
from datetime import datetime, timezone, timedelta
from ingest.adapters.nvd import NVDAdapter

logging.basicConfig(level=logging.DEBUG)

async def main():
    adapter = NVDAdapter()
    since = datetime.now(timezone.utc) - timedelta(hours=1)
    until = datetime.now(timezone.utc)
    print('Calling NVD with since=%s until=%s' % (since.isoformat(), until.isoformat()))
    res = await adapter.fetch(start_index=0, results_per_page=10, since=since, until=until)
    print('FETCH_DONE', res.get('totalResults'), len(res.get('vulnerabilities', [])))

if __name__ == '__main__':
    asyncio.run(main())
