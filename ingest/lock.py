import hashlib
import logging
from typing import Any

from app import database

logger = logging.getLogger(__name__)


def _advisory_key(name: str) -> int:
    h = hashlib.sha256(name.encode('utf-8')).digest()[:8]
    val = int.from_bytes(h, 'big')
    return val % (2**63 - 1)


class PgAdvisoryLock:
    """Context manager using Postgres advisory transaction-scoped locks.

    Usage:
        async with PgAdvisoryLock('nvd') as conn:
            # conn is asyncpg.Connection inside a transaction
            await conn.execute(...)
    """

    def __init__(self, name: str):
        self._name = name
        self._key = _advisory_key(name)
        self._conn = None
        self._txn = None

    async def __aenter__(self) -> Any:
        if not database._HAS_ASYNCPG:
            raise RuntimeError('asyncpg is required for DB locks')
        if not database.db_pool.pool:
            await database.db_pool.initialize()
        self._conn = await database.db_pool.pool.acquire()
        self._txn = self._conn.transaction()
        await self._txn.start()
        await self._conn.execute('SELECT pg_advisory_xact_lock($1)', self._key)
        logger.info('Acquired advisory lock %s (key=%s)', self._name, self._key)
        return self._conn

    async def __aexit__(self, exc_type, exc, tb):
        try:
            if exc_type is None:
                await self._txn.commit()
            else:
                await self._txn.rollback()
        finally:
            if self._conn:
                await database.db_pool.pool.release(self._conn)
                self._conn = None
