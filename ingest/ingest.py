"""
Simplified CVE data ingestion for JSONB-based storage
Handles NVD and CISA KEV data sources
"""
import asyncio
import aiohttp
import json
import logging
import sys
import os
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from pathlib import Path
import gzip

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

from app.database import (
    db_pool, 
    store_nvd_cves_batch, 
    store_cisa_kevs_batch,
    refresh_materialized_view
)
from app.database import AdvisoryXactLock

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class CVEIngester:
    """Simplified CVE data ingestion system"""
    
    def __init__(self):
        self.session = None
        self.nvd_api_key = os.getenv('NVD_API_KEY')  # Optional but recommended
        
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=300)  # 5 minute timeout
        )
        await db_pool.initialize()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
        await db_pool.close()

    async def _get_json_with_retries(self, url: str, *, params: dict | None = None, headers: dict | None = None,
                                     max_retries: int = 5, base_delay: float = 1.0) -> Optional[dict]:
        """
        Perform a GET request and return parsed JSON with retries and backoff.
        Handles 429/5xx responses with Retry-After where available.
        """
        attempt = 0
        headers = headers or {}
        # Ask for gzip responses
        headers.setdefault('Accept-Encoding', 'gzip, deflate')

        while attempt < max_retries:
            attempt += 1
            try:
                logger.debug(f"GET {url} attempt {attempt}")
                async with self.session.get(url, params=params, headers=headers) as resp:
                    status = resp.status
                    if status == 200:
                        # aiohttp auto-decompresses and json() handles encoding
                        data = await resp.json(content_type=None)
                        return data

                    # Handle rate limiting
                    if status in (429, 503) or 500 <= status < 600:
                        retry_after = None
                        try:
                            retry_after = int(resp.headers.get('Retry-After'))
                        except Exception:
                            retry_after = None

                        if retry_after:
                            delay = retry_after
                        else:
                            delay = base_delay * (2 ** (attempt - 1))
                            if delay > 30:
                                delay = 30

                        logger.warning(f"Request to {url} returned {status}. Backing off for {delay}s (attempt {attempt}/{max_retries})")
                        await asyncio.sleep(delay)
                        continue

                    # Other client errors, no retry
                    text = await resp.text()
                    logger.error(f"Request to {url} failed with status {status}: {text}")
                    return None

            except asyncio.CancelledError:
                raise
            except Exception as e:
                # Network-level errors
                delay = base_delay * (2 ** (attempt - 1))
                if delay > 30:
                    delay = 30
                logger.warning(f"Network error fetching {url}: {e} (attempt {attempt}/{max_retries}), retrying in {delay}s")
                await asyncio.sleep(delay)

        logger.error(f"Exceeded max retries fetching {url}")
        return None
    
    async def fetch_nvd_cves(self, start_index: int = 0, results_per_page: int = 2000) -> Optional[Dict[str, Any]]:
        """
        Fetch CVE data from NVD API
        
        Args:
            start_index: Starting index for pagination
            results_per_page: Number of results per request (max 2000)
        
        Returns:
            NVD API response data or None if failed
        """
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        headers = {}
        if self.nvd_api_key:
            headers['apiKey'] = self.nvd_api_key
        
        params = {
            'startIndex': start_index,
            'resultsPerPage': min(results_per_page, 2000)  # NVD limit
        }
        
        logger.info(f"Fetching NVD CVEs: startIndex={start_index}, resultsPerPage={params['resultsPerPage']}")

        # Use robust helper with retries
        data = await self._get_json_with_retries(url, params=params, headers=headers,
                                                max_retries=int(os.getenv('NVD_MAX_RETRIES', '6')),
                                                base_delay=float(os.getenv('NVD_BASE_DELAY', '1.5')))
        if data is None:
            logger.error("Failed to fetch NVD data after retries")
            return None

        # NVD returns object with 'vulnerabilities' list
        logger.info(f"Successfully fetched {len(data.get('vulnerabilities', []))} CVEs from NVD")
        return data
    
    async def process_nvd_cves(self, nvd_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process NVD CVE data into our storage format
        
        Args:
            nvd_data: Raw NVD API response
        
        Returns:
            List of processed CVE records ready for database storage
        """
        processed_cves = []
        
        for vuln in nvd_data.get('vulnerabilities', []):
            cve_data = vuln.get('cve', {})
            cve_id = cve_data.get('id')
            
            if not cve_id:
                logger.warning("Skipping vulnerability without CVE ID")
                continue
            
            try:
                # Extract timestamps
                published_str = cve_data.get('published')
                modified_str = cve_data.get('lastModified')
                
                if not published_str or not modified_str:
                    logger.warning(f"Skipping {cve_id}: missing timestamps")
                    continue
                
                # Parse timestamps (NVD format: 2024-01-15T10:15:08.123)
                published = datetime.fromisoformat(published_str.replace('Z', '+00:00'))
                last_modified = datetime.fromisoformat(modified_str.replace('Z', '+00:00'))
                
                # Extract source if available
                source = None
                if 'sourceIdentifier' in cve_data:
                    source = cve_data['sourceIdentifier']
                
                processed_cve = {
                    'cve_id': cve_id,
                    'published': published,
                    'last_modified': last_modified,
                    'source': source,
                    'data': vuln  # Store the full vulnerability object
                }
                
                processed_cves.append(processed_cve)
                
            except Exception as e:
                logger.error(f"Error processing CVE {cve_id}: {e}")
                continue
        
        logger.info(f"Processed {len(processed_cves)} CVEs from NVD data")
        return processed_cves
    
    async def ingest_nvd_cves(self, max_cves: Optional[int] = None) -> int:
        """
        Ingest CVE data from NVD API
        
        Args:
            max_cves: Maximum number of CVEs to ingest (None = all)
        
        Returns:
            Total number of CVEs ingested
        """
        total_ingested = 0
        start_index = 0
        results_per_page = 2000
        
        logger.info("Starting NVD CVE ingestion")
        
        while True:
            # Fetch batch from NVD
            nvd_data = await self.fetch_nvd_cves(start_index, results_per_page)
            if not nvd_data:
                logger.error("Failed to fetch NVD data, stopping ingestion")
                break

            vulnerabilities = nvd_data.get('vulnerabilities', [])
            if not vulnerabilities:
                logger.info("No more vulnerabilities to process")
                break

            # Only process/store up to max_cves
            remaining = max_cves - total_ingested if max_cves else None
            if remaining is not None and remaining < len(vulnerabilities):
                vulnerabilities = vulnerabilities[:remaining]
                nvd_data['vulnerabilities'] = vulnerabilities

            processed_cves = await self.process_nvd_cves(nvd_data)

            if processed_cves:
                async with AdvisoryXactLock('nvd') as conn:
                    stored_count = await store_nvd_cves_batch(processed_cves, conn=conn)
                total_ingested += stored_count
                logger.info(f"Stored {stored_count} CVEs (total: {total_ingested})")

            total_results = nvd_data.get('totalResults', 0)
            start_index += len(vulnerabilities)

            if max_cves and total_ingested >= max_cves:
                logger.info(f"Reached maximum CVE limit: {max_cves}")
                break

            if start_index >= total_results:
                logger.info("Reached end of NVD data")
                break

            if not self.nvd_api_key:
                await asyncio.sleep(0.6)

        logger.info(f"NVD ingestion complete. Total ingested: {total_ingested}")
        return total_ingested
    
    async def fetch_cisa_kev(self) -> Optional[Dict[str, Any]]:
        """
        Fetch CISA Known Exploited Vulnerabilities catalog
        
        Returns:
            CISA KEV data or None if failed
        """
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        logger.info("Fetching CISA KEV catalog")

        data = await self._get_json_with_retries(url,
                                                max_retries=int(os.getenv('CISA_MAX_RETRIES', '4')),
                                                base_delay=float(os.getenv('CISA_BASE_DELAY', '1.0')))
        if data is None:
            logger.error("Failed to fetch CISA KEV data after retries")
            return None

        # Some feeds may be a list or use a 'vulnerabilities' key
        if isinstance(data, dict) and 'vulnerabilities' in data:
            count = len(data.get('vulnerabilities', []))
        elif isinstance(data, list):
            # normalize to dict format
            data = {'vulnerabilities': data}
            count = len(data['vulnerabilities'])
        else:
            count = 0

        logger.info(f"Successfully fetched CISA KEV catalog with {count} entries")
        return data
    
    async def process_cisa_kevs(self, kev_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Process CISA KEV data into our storage format
        
        Args:
            kev_data: Raw CISA KEV data
        
        Returns:
            List of processed KEV records ready for database storage
        """
        processed_kevs = []
        for vuln in kev_data.get('vulnerabilities', []):
            cve_id = vuln.get('cveID') or vuln.get('cve_id')
            if not cve_id:
                logger.warning("Skipping KEV entry without CVE ID")
                continue
            try:
                # Parse date fields
                date_added_str = vuln.get('dateAdded')
                due_date_str = vuln.get('dueDate')
                date_added = None
                due_date = None
                if date_added_str:
                    date_added = datetime.strptime(date_added_str, '%Y-%m-%d').date()
                if due_date_str:
                    due_date = datetime.strptime(due_date_str, '%Y-%m-%d').date()
                processed_kev = {
                    'cve_id': cve_id,
                    'vendor_project': vuln.get('vendorProject') or vuln.get('vendor_project'),
                    'product': vuln.get('product'),
                    'date_added': date_added,
                    'required_action': vuln.get('requiredAction') or vuln.get('required_action'),
                    'due_date': due_date,
                    'data': vuln
                }
                processed_kevs.append(processed_kev)
            except Exception as e:
                logger.error(f"Error processing KEV {cve_id}: {e}")
                continue
        logger.info(f"Processed {len(processed_kevs)} KEV records")
        return processed_kevs
    
    async def ingest_cisa_kevs(self) -> int:
        """
        Ingest CISA Known Exploited Vulnerabilities
        
        Returns:
            Number of KEVs ingested
        """
        logger.info("Starting CISA KEV ingestion")
        
        # Fetch CISA KEV data
        kev_data = await self.fetch_cisa_kev()
        if not kev_data:
            logger.error("Failed to fetch CISA KEV data")
            return 0
        
        # Process the KEVs
        processed_kevs = await self.process_cisa_kevs(kev_data)
        
        # Store in database inside a transaction-scoped advisory lock
        if processed_kevs:
            async with AdvisoryXactLock('cisa') as conn:
                stored_count = await store_cisa_kevs_batch(processed_kevs, conn=conn)
            logger.info(f"CISA KEV ingestion complete. Stored: {stored_count}")
            return stored_count
        
        return 0
    
    async def run_full_ingestion(self, max_cves: Optional[int] = None) -> Dict[str, int]:
        """
        Run complete ingestion of both NVD and CISA data
        
        Args:
            max_cves: Maximum number of CVEs to ingest from NVD
        
        Returns:
            Dict with ingestion counts
        """
        logger.info("Starting full CVE data ingestion")
        
        # Ingest NVD CVEs
        nvd_count = await self.ingest_nvd_cves(max_cves)
        
        # Ingest CISA KEVs
        kev_count = await self.ingest_cisa_kevs()
        
        # Refresh materialized view
        logger.info("Refreshing materialized view")
        await refresh_materialized_view()
        
        results = {
            'nvd_cves': nvd_count,
            'cisa_kevs': kev_count,
            'total': nvd_count + kev_count
        }
        
        logger.info(f"Full ingestion complete: {results}")
        return results


async def main():
    """Main ingestion function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='CVE Data Ingestion')
    parser.add_argument('--max-cves', type=int, help='Maximum number of CVEs to ingest')
    parser.add_argument('--nvd-only', action='store_true', help='Ingest only NVD data')
    parser.add_argument('--kev-only', action='store_true', help='Ingest only CISA KEV data')
    
    args = parser.parse_args()
    
    async with CVEIngester() as ingester:
        if args.nvd_only:
            count = await ingester.ingest_nvd_cves(args.max_cves)
            print(f"Ingested {count} NVD CVEs")
        elif args.kev_only:
            count = await ingester.ingest_cisa_kevs()
            print(f"Ingested {count} CISA KEVs")
        else:
            results = await ingester.run_full_ingestion(args.max_cves)
            print(f"Ingestion complete: {results}")

if __name__ == "__main__":
    asyncio.run(main())