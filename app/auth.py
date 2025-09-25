"""
JWT Auth (RS256) integration for FastAPI using JWKS discovery.

Reads AUTH_ISSUER (and optional JWT_AUDIENCE) from env, fetches
the issuer's JWKS, and verifies incoming Bearer tokens.

Usage (in FastAPI routes):

    from .auth import require_auth

    @app.get('/admin/secure')
    async def secure_endpoint(claims = Depends(require_auth(['admin']))):
        return { 'sub': claims['sub'] }
"""
from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Optional

import httpx
from fastapi import Header, HTTPException, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt
from jose.utils import base64url_decode
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


AUTH_ISSUER = os.getenv('AUTH_ISSUER', 'http://localhost:8001').rstrip('/')
JWT_AUDIENCE = os.getenv('JWT_AUDIENCE')  # optional
JWKS_URL = os.getenv('AUTH_JWKS_URL') or f"{AUTH_ISSUER}/.well-known/jwks.json"
ALGO = 'RS256'

# Expose a Bearer security scheme so Swagger UI shows the Authorize button
_bearer_scheme = HTTPBearer(auto_error=False)


class _JWKSCache:
    def __init__(self, url: str, ttl_seconds: int = 600):
        self.url = url
        self.ttl = max(60, int(ttl_seconds))
        self._cache: Dict[str, Any] = {}
        self._fetched_at: float = 0.0

    async def _fetch(self) -> Dict[str, Any]:
        timeout = httpx.Timeout(10.0, connect=5.0)
        async with httpx.AsyncClient(timeout=timeout) as client:
            resp = await client.get(self.url)
            resp.raise_for_status()
            return resp.json()

    async def get_keys(self) -> Dict[str, Dict[str, Any]]:
        now = time.time()
        if (now - self._fetched_at) > self.ttl or not self._cache:
            body = await self._fetch()
            keys = {k['kid']: k for k in body.get('keys', []) if 'kid' in k}
            self._cache = keys
            self._fetched_at = now
        return self._cache

    async def get_key_by_kid(self, kid: str) -> Optional[Dict[str, Any]]:
        keys = await self.get_keys()
        key = keys.get(kid)
        if key is None:
            # force refresh once in case of rotation
            self._fetched_at = 0.0
            keys = await self.get_keys()
            key = keys.get(kid)
        return key


_jwks_cache = _JWKSCache(JWKS_URL)


def _rsa_key_from_jwk(jwk_dict: Dict[str, Any]):
    """Build an RSA public key from a JWKS RSA key dict (n/e are base64url strings)."""
    try:
        n_b = base64url_decode(str(jwk_dict['n']).encode('ascii'))
        e_b = base64url_decode(str(jwk_dict['e']).encode('ascii'))
    except Exception as ex:
        # Re-raise as a clear auth error
        raise HTTPException(status_code=401, detail='Invalid JWKS key material') from ex
    n = int.from_bytes(n_b, 'big')
    e = int.from_bytes(e_b, 'big')
    return rsa.RSAPublicNumbers(e, n).public_key(default_backend())


async def verify_token(token: str) -> Dict[str, Any]:
    try:
        header = jwt.get_unverified_header(token)
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid token header')

    kid = header.get('kid')
    if not kid:
        raise HTTPException(status_code=401, detail='Missing kid')

    key = await _jwks_cache.get_key_by_kid(kid)
    if not key:
        raise HTTPException(status_code=401, detail='Unknown signing key')

    public_key = _rsa_key_from_jwk(key)

    options = {
        'verify_aud': bool(JWT_AUDIENCE),
    }
    try:
        claims = jwt.decode(
            token,
            public_key,
            algorithms=[ALGO],
            issuer=AUTH_ISSUER,
            audience=JWT_AUDIENCE if JWT_AUDIENCE else None,
            options=options,
        )
        return claims
    except Exception:
        raise HTTPException(status_code=401, detail='Invalid token')


def require_auth(roles: Optional[List[str]] = None):
    roles = roles or []

    async def _dep(
        authorization: str | None = Header(default=None),
        credentials: Optional[HTTPAuthorizationCredentials] = Security(_bearer_scheme)
    ):
        token: Optional[str] = None
        if credentials and credentials.scheme and credentials.scheme.lower() == 'bearer' and credentials.credentials:
            token = credentials.credentials
        elif authorization and authorization.startswith('Bearer '):
            token = authorization.split(' ', 1)[1]
        if not token:
            raise HTTPException(status_code=401, detail='Missing token')
        claims = await verify_token(token)
        if roles:
            user_roles = set(claims.get('roles', []))
            if not set(roles) & user_roles:
                raise HTTPException(status_code=403, detail='Insufficient role')
        return claims

    return _dep
