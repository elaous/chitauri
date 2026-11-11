"""Fetches and caches Google's hardware attestation revocation list."""
from __future__ import annotations

import time

import httpx

from app.constants import GOOGLE_REVOCATION_LIST_URL

_cache: dict = {"data": None, "fetched_at": 0.0}
_CACHE_TTL_SECONDS = 3600


def _fetch() -> dict:
    resp = httpx.get(GOOGLE_REVOCATION_LIST_URL, timeout=10.0)
    resp.raise_for_status()
    return resp.json()


def get_revocation_list(force_refresh: bool = False) -> dict:
    now = time.time()
    if (
        force_refresh
        or _cache["data"] is None
        or now - _cache["fetched_at"] > _CACHE_TTL_SECONDS
    ):
        _cache["data"] = _fetch()
        _cache["fetched_at"] = now
    return _cache["data"]


def is_revoked(serial_number_hex: str) -> tuple[bool, str | None]:
    """Absence from the list means not known revoked, not valid."""
    data = get_revocation_list()
    entry = data.get("entries", {}).get(serial_number_hex.lower())
    if entry is None:
        return False, None
    return True, entry.get("status")
