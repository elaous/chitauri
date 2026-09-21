"""Loads the allowlist / policy config from config/allowlist.yaml."""
from __future__ import annotations

import pathlib
from functools import lru_cache

import yaml

CONFIG_PATH = pathlib.Path(__file__).resolve().parent.parent / "config" / "allowlist.yaml"

# Google's published hardware attestation revocation status list.
# See https://security.googleblog.com/2019/09/trust-but-verify-attestation-with.html
GOOGLE_REVOCATION_LIST_URL = "https://android.googleapis.com/attestation/status"


@lru_cache
def load_config() -> dict:
    with open(CONFIG_PATH, "r") as f:
        return yaml.safe_load(f)


def get_os_profile(os_id: str) -> dict | None:
    cfg = load_config()
    for entry in cfg.get("os_allowlist", []):
        if entry["id"] == os_id:
            return entry
    return None


def get_policy() -> dict:
    return load_config().get("policy", {})
