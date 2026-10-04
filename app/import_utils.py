"""Shared parsing for the verified-boot-key import paths (HTTP admin
endpoints in app/admin.py, and the scripts/import_verified_boot_keys.py CLI).

Both CSV and JSON import ultimately produce a list of (os_id, VerifiedBootKeyData)
pairs grouped by os_id, which app.storage.ConfigStore.add_verified_boot_keys
can insert directly.
"""
from __future__ import annotations

import csv
import io

from app.storage.base import ConfigValidationError, VerifiedBootKeyData

CSV_COLUMNS = ("os_id", "device", "release", "verified_boot_key_sha256")


def group_by_os_id(
    rows: list[tuple[str, VerifiedBootKeyData]]
) -> dict[str, list[VerifiedBootKeyData]]:
    grouped: dict[str, list[VerifiedBootKeyData]] = {}
    for os_id, key in rows:
        grouped.setdefault(os_id, []).append(key)
    return grouped


def parse_json_rows(
    records: list[dict], *, default_os_id: str | None = None
) -> list[tuple[str, VerifiedBootKeyData]]:
    """`records` is a list of objects with keys: os_id (optional if
    `default_os_id` given), device, release, verified_boot_key_sha256."""
    rows: list[tuple[str, VerifiedBootKeyData]] = []
    for i, record in enumerate(records):
        os_id = record.get("os_id") or default_os_id
        if not os_id:
            raise ConfigValidationError(f"Row {i}: missing 'os_id' and no default given")
        if "verified_boot_key_sha256" not in record:
            raise ConfigValidationError(f"Row {i}: missing 'verified_boot_key_sha256'")
        key = VerifiedBootKeyData(
            verified_boot_key_sha256=record["verified_boot_key_sha256"],
            device=record.get("device"),
            release=record.get("release"),
        )
        rows.append((os_id, key))
    return rows


def parse_csv_rows(
    text: str, *, default_os_id: str | None = None
) -> list[tuple[str, VerifiedBootKeyData]]:
    """CSV columns: os_id,device,release,verified_boot_key_sha256 — `os_id`
    may be omitted from the file entirely if `default_os_id` is given."""
    reader = csv.DictReader(io.StringIO(text))
    if reader.fieldnames is None:
        return []

    unknown = set(reader.fieldnames) - set(CSV_COLUMNS)
    if unknown:
        raise ConfigValidationError(f"Unknown CSV column(s): {sorted(unknown)}")

    rows: list[tuple[str, VerifiedBootKeyData]] = []
    for i, record in enumerate(reader):
        os_id = (record.get("os_id") or "").strip() or default_os_id
        if not os_id:
            raise ConfigValidationError(f"Row {i}: missing 'os_id' column and no default given")
        sha256 = (record.get("verified_boot_key_sha256") or "").strip()
        if not sha256:
            raise ConfigValidationError(f"Row {i}: missing 'verified_boot_key_sha256' column")
        key = VerifiedBootKeyData(
            verified_boot_key_sha256=sha256,
            device=(record.get("device") or "").strip() or None,
            release=(record.get("release") or "").strip() or None,
        )
        rows.append((os_id, key))
    return rows
