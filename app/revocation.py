"""
Fetches and caches Google's Android hardware attestation key revocation
status list. See:
https://security.googleblog.com/2019/09/trust-but-verify-attestation-with.html

The list is JSON: {"entries": {"<serial-hex>": {"status": "REVOKED"|"SUSPENDED", "reason": "..."}}}
Only non-valid keys are listed, so absence means "not known to be revoked" —
not a positive guarantee, just the best signal Google publishes.
"""
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
    """serial_number_hex should be lowercase, no leading zeros stripped oddly —
    match Google's format exactly; verify against a real response before
    trusting this in production."""
    data = get_revocation_list()
    entry = data.get("entries", {}).get(serial_number_hex.lower())
    if entry is None:
        return False, None
    return True, entry.get("status")
