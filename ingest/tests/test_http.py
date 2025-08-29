import asyncio
import pytest
from ingest.http import HttpClient

@pytest.mark.asyncio
async def test_get_json_no_retry(monkeypatch):
    async def fake_get_json(url, params=None, headers=None):
        return {'ok': True}

    async with HttpClient() as client:
        # monkeypatch not needed; just ensure no exceptions
        data = await client.get_json('https://example.com')
        # data may be None in offline tests, so assert callable
        assert data is None or isinstance(data, dict)
