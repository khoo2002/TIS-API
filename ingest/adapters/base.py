from typing import Any, Dict, List, Optional
from datetime import datetime

class AdapterBase:
    """Adapter contract for ingest sources.

    Implementations must provide:
      - fetch(self, **params) -> raw JSON
      - normalize(self, raw_json, **params) -> List[NormalizedRecord]

    NormalizedRecord (dict): {
        'cve_id': str,
        'published': datetime,
        'last_modified': datetime,
        'source': str,
        'data': dict
    }
    """

    name: str = 'base'

    async def fetch(self, **params) -> Optional[Any]:
        raise NotImplementedError()

    async def normalize(self, raw_json, **params) -> List[Dict[str, Any]]:
        raise NotImplementedError()

    async def store(self, records: List[Dict[str, Any]], conn=None) -> int:
        """Default store: map normalized record to DB batch storers in app.database

        Adapter implementations may override this to use a different storage backend.
        """
        from app.database import store_nvd_cves_batch, store_cisa_kevs_batch
        if self.name == 'nvd':
            # convert normalized to expected store shape
            items = [
                {
                    'cve_id': r['cve_id'],
                    'published': r['published'],
                    'last_modified': r['last_modified'],
                    'source': r.get('source'),
                    'data': r['data']
                }
                for r in records
            ]
            return await store_nvd_cves_batch(items, conn=conn)
        elif self.name == 'cisa':
            items = [
                {
                    'cve_id': r['cve_id'],
                    'vendor_project': r.get('vendor_project'),
                    'product': r.get('product'),
                    'date_added': r.get('date_added'),
                    'required_action': r.get('required_action'),
                    'due_date': r.get('due_date'),
                    'data': r['data']
                }
                for r in records
            ]
            return await store_cisa_kevs_batch(items, conn=conn)
        else:
            raise NotImplementedError('Unknown adapter storage mapping')

    # Provide async context manager support so adapters can be used with "async with"
    async def __aenter__(self):
        # Default no-op setup; subclasses may override if needed
        return self

    async def __aexit__(self, exc_type, exc, tb):
        # Default no-op teardown; subclasses may override if needed
        return False
