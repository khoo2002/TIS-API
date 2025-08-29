from .base import AdapterBase
from ..http import HttpClient
from datetime import datetime
from typing import List, Dict, Any, Optional

class CISAAdapter(AdapterBase):
    name = 'cisa'

    async def fetch(self, since=None, until=None, **params):
        """Fetch CISA KEV data. Since CISA provides a static JSON file, 
        we always fetch the complete dataset but can filter by since/until dates."""
        url = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
        async with HttpClient() as http:
            data = await http.get_json(url)
        
        # Store the since/until parameters to use in normalize()
        if hasattr(data, '__dict__'):
            data._filter_since = since
            data._filter_until = until
        else:
            # For dict responses, we'll pass filtering info via params in normalize
            pass
            
        return data

    async def normalize(self, raw_json, since=None, until=None, **params) -> List[Dict[str, Any]]:
        """Normalize CISA KEV data with optional date filtering."""
        out = []
        items = raw_json.get('vulnerabilities') if isinstance(raw_json, dict) else (raw_json if isinstance(raw_json, list) else [])
        
        for vuln in items:
            cve_id = vuln.get('cveID') or vuln.get('cve_id')
            if not cve_id:
                continue
                
            date_added = None
            due_date = None
            try:
                if vuln.get('dateAdded'):
                    date_added = datetime.strptime(vuln.get('dateAdded'), '%Y-%m-%d').date()
                if vuln.get('dueDate'):
                    due_date = datetime.strptime(vuln.get('dueDate'), '%Y-%m-%d').date()
            except Exception:
                pass
            
            # Apply since/until filtering based on dateAdded
            if since is not None and date_added is not None:
                # Convert since to date for comparison if it's a datetime
                since_date = since.date() if hasattr(since, 'date') else since
                if date_added < since_date:
                    continue  # Skip records older than since date
                    
            if until is not None and date_added is not None:
                # Convert until to date for comparison if it's a datetime  
                until_date = until.date() if hasattr(until, 'date') else until
                if date_added > until_date:
                    continue  # Skip records newer than until date
            
            out.append({
                'cve_id': cve_id,
                'vendor_project': vuln.get('vendorProject') or vuln.get('vendor_project'),
                'product': vuln.get('product'),
                'date_added': date_added,
                'required_action': vuln.get('requiredAction') or vuln.get('required_action'),
                'due_date': due_date,
                'data': vuln
            })
        return out
