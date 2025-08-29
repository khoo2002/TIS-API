import pytest

from ingest.adapters.nvd import NVDAdapter

@pytest.mark.asyncio
async def test_nvd_normalize_sample():
    adapter = NVDAdapter()
    sample = {'vulnerabilities': [{'cve': {'id': 'CVE-2025-0001', 'published': '2025-01-01T00:00:00Z', 'lastModified': '2025-01-02T00:00:00Z', 'sourceIdentifier': 'NVD'}}]}
    out = await adapter.normalize(sample)
    assert isinstance(out, list)
    assert out[0]['cve_id'] == 'CVE-2025-0001'
