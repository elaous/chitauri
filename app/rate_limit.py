"""Shared slowapi Limiter and enforce() dependency helper."""
from __future__ import annotations

import limits
from fastapi import HTTPException, Request
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)


def enforce(rate: str, *, scope: str):
    """Per-client-IP rate limit dependency. Place before auth dependencies."""
    limit_item = limits.parse(rate)

    async def _dependency(request: Request) -> None:
        key = limiter._key_func(request)
        if not limiter.limiter.hit(limit_item, key, scope):
            raise HTTPException(429, f"Rate limit exceeded: {rate}")

    return _dependency
