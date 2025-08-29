import asyncio
import logging
from typing import Optional, Dict, Any
import aiohttp

logger = logging.getLogger(__name__)

class HttpClient:
    """Simple HTTP client with retries, exponential backoff and Retry-After handling.

    Usage:
        async with HttpClient() as http:
            data = await http.get_json(url)
    """

    def __init__(self, max_retries: int = 5, base_delay: float = 1.0, timeout: int = 300):
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.timeout = timeout
        self.session: Optional[aiohttp.ClientSession] = None

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=self.timeout))
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.session:
            await self.session.close()

    async def get_json(self, url: str, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Optional[Any]:
        attempt = 0
        headers = headers or {}
        headers.setdefault('Accept-Encoding', 'gzip, deflate')
        while attempt < self.max_retries:
            attempt += 1
            try:
                logger.debug('HTTP GET %s params=%s headers=%s', url, params, {k: (v if k.lower() != 'apikey' else 'REDACTED') for k, v in headers.items()})
                async with self.session.get(url, params=params, headers=headers) as resp:
                    status = resp.status
                    if status == 200:
                        return await resp.json(content_type=None)
                    if status in (429, 503) or 500 <= status < 600:
                        retry_after = resp.headers.get('Retry-After')
                        if retry_after:
                            try:
                                delay = int(retry_after)
                            except Exception:
                                delay = self.base_delay * (2 ** (attempt - 1))
                        else:
                            delay = self.base_delay * (2 ** (attempt - 1))
                            if delay > 30:
                                delay = 30
                        logger.warning("%s returned %s, backing off %ss (attempt %s)", url, status, delay, attempt)
                        await asyncio.sleep(delay)
                        continue
                    text = await resp.text()
                    logger.error("GET %s failed %s: %s", url, status, text)
                    return None
            except asyncio.CancelledError:
                raise
            except Exception as e:
                delay = self.base_delay * (2 ** (attempt - 1))
                if delay > 30:
                    delay = 30
                logger.warning("Network error fetching %s: %s (attempt %s), retrying in %s", url, e, attempt, delay)
                await asyncio.sleep(delay)
        logger.error("Exceeded max retries fetching %s", url)
        return None
