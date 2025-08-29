import asyncio
import logging
import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent))

from ingest import ingest as ingest_module

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger('run_test_ingest')

async def run():
    async with ingest_module.CVEIngester() as ing:
        res = await ing.run_full_ingestion(max_cves=5)
        logger.info(f"Run result: {res}")

if __name__ == '__main__':
    asyncio.run(run())
