"""Shared slowapi Limiter instance, plus a dependency-based enforcement
helper for routes where ordering matters.

A single module so app/main.py and app/admin.py (which app/main.py imports)
can both decorate routes with it without a circular import. Limits
themselves are read from app.settings at decoration/call time, so set them
via env vars before the process starts, not at request time.

Two ways to apply a limit:

- `@limiter.limit("20/minute")` on a route function — the usual slowapi
  decorator. Fine for routes with no other dependency that can reject the
  request first (e.g. /nonce, /verify), since FastAPI only calls the
  (decorated) endpoint function, where the check actually runs, after every
  `Depends`/`dependencies=[...]` has already succeeded.
- `Depends(enforce("20/minute", scope="admin"))`, placed *before*
  `Depends(require_admin)` in a route's `dependencies=[...]` list — for
  routes where the limit must apply even when a later dependency (like API
  key auth) would otherwise reject the request first. Without this, failed
  auth attempts would never be counted, defeating rate limiting as a
  brute-force guard on the admin API key.
"""
from __future__ import annotations

import limits
from fastapi import HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)


def enforce(rate: str, *, scope: str):
    """Returns a FastAPI dependency enforcing `rate` (e.g. "30/minute") per
    client IP, under `scope`, using the same storage as `limiter` (so
    `limiter.reset()` also resets this)."""
    limit_item = limits.parse(rate)

    async def _dependency(request: Request) -> None:
        key = limiter._key_func(request)
        if not limiter.limiter.hit(limit_item, key, scope):
            raise HTTPException(429, f"Rate limit exceeded: {rate}")

    return _dependency
