from .base import AdapterBase
from ..http import HttpClient
from datetime import datetime, timezone
from urllib.parse import urlencode
from typing import List, Dict, Any, Optional
import logging

logger = logging.getLogger(__name__)

class NVDAdapter(AdapterBase):
    name = 'nvd'

    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key

    async def fetch(self, start_index: int = 0, results_per_page: int = 2000, since: Optional[datetime] = None, until: Optional[datetime] = None):
        """Fetch raw NVD CVE JSON.

        Accepts optional `since`/`until` datetimes which are mapped to
        NVD's `modStartDate`/`modEndDate` (lastModified window) parameters.
        """
        url = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
        headers = {}
        if self.api_key:
            headers['apiKey'] = self.api_key
        params = {'startIndex': start_index, 'resultsPerPage': results_per_page}

        # Map since/until to NVD API date parameters (lastModStartDate/lastModEndDate)
        def _format(dt: datetime) -> str:
            # Normalize to UTC and emit an RFC3339-like Z-terminated timestamp
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            dt_utc = dt.astimezone(timezone.utc)
            # milliseconds precision which NVD accepts
            return dt_utc.isoformat(timespec='milliseconds').replace('+00:00', 'Z')

        if since:
            params['lastModStartDate'] = _format(since)
        if until:
            params['lastModEndDate'] = _format(until)

        async with HttpClient() as http:
            # Log the final request for debugging (URL + params + headers sans sensitive)
            try:
                log_params = dict(params)
                log_headers = {k: (v if k.lower() != 'apikey' else 'REDACTED') for k, v in headers.items()}
                logger.debug('NVD request params=%s headers=%s', log_params, log_headers)
                try:
                    qs = urlencode(params, doseq=True)
                    logger.info('NVD full URL: %s?%s', url, qs)
                    # Also print to stdout so container logs capture it regardless of logger config
                    print(f'NVD_FULL_URL {url}?{qs}')
                except Exception:
                    logger.debug('NVD full URL: unable to build querystring')
            except Exception:
                logger.debug('NVD request (unable to serialize params/headers)')

            # Return the raw JSON so callers can inspect pagination metadata
            return await http.get_json(url, params=params, headers=headers)

    async def normalize(self, raw_json, **params) -> List[Dict[str, Any]]:
        out = []
        for vuln in raw_json.get('vulnerabilities', []):
            cve = vuln.get('cve', {})
            cve_id = cve.get('id')
            if not cve_id:
                continue
            published = None
            last_modified = None
            try:
                published = datetime.fromisoformat(cve.get('published').replace('Z', '+00:00'))
                last_modified = datetime.fromisoformat(cve.get('lastModified').replace('Z', '+00:00'))
            except Exception:
                continue
            out.append({
                'cve_id': cve_id,
                'published': published,
                'last_modified': last_modified,
                'source': cve.get('sourceIdentifier'),
                'data': vuln
            })
        return out
