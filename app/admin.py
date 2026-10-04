"""Admin endpoints for managing the allowlist/policy config.

Four ways to insert verified_boot_keys, covering single/bulk x JSON/CSV:

  POST /admin/verified-boot-keys              single record, JSON body
  POST /admin/verified-boot-keys/bulk         many records, JSON array body
  POST /admin/verified-boot-keys/import       many records, multipart CSV file
  POST /admin/verified-boot-keys/import/row   single record, raw CSV body (one line)

All of these (and the os-profile endpoints) require the `X-Admin-Api-Key`
header to match `settings.admin_api_key`. The admin API is disabled
entirely (503) if that setting is unset — there is no default key.

All of these are also rate-limited per client IP (`settings.rate_limit_admin`,
shared across the whole admin surface), as defense in depth against a
leaked/guessed key. The rate-limit dependency is listed *before*
`require_admin` in each route's `dependencies=[...]` so a request is counted
even when auth then rejects it — otherwise brute-forcing the admin key
would never trip the limiter, since FastAPI only calls the limiter's usual
`@limiter.limit`-decorated endpoint body after every dependency has already
succeeded (see app/rate_limit.py).
"""
from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, UploadFile
from pydantic import BaseModel, Field

from app.import_utils import group_by_os_id, parse_csv_rows, parse_json_rows
from app.rate_limit import enforce
from app.settings import settings
from app.storage import ConfigStore, ConfigValidationError, get_store

router = APIRouter(prefix="/admin", tags=["admin"])


async def require_admin(x_admin_api_key: str = Header(...)) -> None:
    if not settings.admin_api_key:
        raise HTTPException(503, "Admin API is disabled (ADMIN_API_KEY is not set)")
    if not secrets.compare_digest(x_admin_api_key, settings.admin_api_key):
        raise HTTPException(401, "Invalid admin API key")


def _admin_dependencies() -> list:
    return [
        Depends(enforce(settings.rate_limit_admin, scope="admin")),
        Depends(require_admin),
    ]


class OSProfileIn(BaseModel):
    id: str
    display_name: str
    expected_verified_boot_state: str
    require_device_locked: bool = True


class VerifiedBootKeyIn(BaseModel):
    os_id: str
    device: str | None = None
    release: str | None = None
    verified_boot_key_sha256: str = Field(min_length=64, max_length=64)


class ImportResult(BaseModel):
    received: int
    added: int
    by_os_id: dict[str, int]


def _max_rows_guard(n: int) -> None:
    if n > settings.admin_import_max_rows:
        raise HTTPException(
            413,
            f"{n} rows exceeds admin_import_max_rows ({settings.admin_import_max_rows})",
        )


async def _insert_grouped(
    store: ConfigStore, grouped: dict[str, list]
) -> ImportResult:
    # Check every os_id exists *before* writing any of them. A batch can
    # span multiple os_ids (e.g. a CSV covering several OSes); without this,
    # one os_id past the real ones already written would leave those writes
    # persisted even though the whole request reports a single 400 — each
    # add_verified_boot_keys() call commits independently (see
    # PostgresConfigStore/DynamoDBConfigStore), so there's no overall
    # transaction to roll back.
    for os_id in grouped:
        if await store.get_os_profile(os_id) is None:
            raise HTTPException(400, f"Unknown os_id {os_id!r}")

    by_os_id: dict[str, int] = {}
    received = 0
    try:
        for os_id, keys in grouped.items():
            received += len(keys)
            by_os_id[os_id] = await store.add_verified_boot_keys(os_id, keys)
    except ConfigValidationError as e:
        raise HTTPException(400, str(e))
    return ImportResult(received=received, added=sum(by_os_id.values()), by_os_id=by_os_id)


@router.post("/os-profiles", dependencies=_admin_dependencies())
async def upsert_os_profile(
    profile: OSProfileIn, store: ConfigStore = Depends(get_store)
) -> dict[str, str]:
    await store.upsert_os_profile(
        os_id=profile.id,
        display_name=profile.display_name,
        expected_verified_boot_state=profile.expected_verified_boot_state,
        require_device_locked=profile.require_device_locked,
    )
    return {"status": "ok", "id": profile.id}


@router.post("/verified-boot-keys", dependencies=_admin_dependencies())
async def add_verified_boot_key(
    key: VerifiedBootKeyIn, store: ConfigStore = Depends(get_store)
) -> ImportResult:
    try:
        grouped = group_by_os_id(parse_json_rows([key.model_dump()]))
    except ConfigValidationError as e:
        raise HTTPException(400, str(e))
    return await _insert_grouped(store, grouped)


@router.post("/verified-boot-keys/bulk", dependencies=_admin_dependencies())
async def add_verified_boot_keys_bulk(
    keys: list[VerifiedBootKeyIn], store: ConfigStore = Depends(get_store)
) -> ImportResult:
    _max_rows_guard(len(keys))
    try:
        grouped = group_by_os_id(parse_json_rows([k.model_dump() for k in keys]))
    except ConfigValidationError as e:
        raise HTTPException(400, str(e))
    return await _insert_grouped(store, grouped)


@router.post("/verified-boot-keys/import", dependencies=_admin_dependencies())
async def import_verified_boot_keys_csv(
    file: UploadFile,
    default_os_id: str | None = Query(
        None, description="os_id to use for rows that omit the os_id column"
    ),
    store: ConfigStore = Depends(get_store),
) -> ImportResult:
    # Starlette has already fully spooled the multipart body to construct
    # `file` by the time this handler runs (FastAPI parses the whole form
    # before calling the endpoint), so this doesn't avoid buffering an
    # oversized upload — it only stops us going on to parse/insert rows
    # from one. A real "reject before buffering" guard would need to check
    # Content-Length ahead of form parsing (e.g. in middleware).
    if file.size is not None and file.size > settings.admin_import_max_file_bytes:
        raise HTTPException(
            413,
            f"File too large ({file.size} bytes, max "
            f"{settings.admin_import_max_file_bytes})",
        )
    content = (await file.read()).decode("utf-8-sig")
    try:
        rows = parse_csv_rows(content, default_os_id=default_os_id)
    except ConfigValidationError as e:
        raise HTTPException(400, str(e))
    _max_rows_guard(len(rows))
    return await _insert_grouped(store, group_by_os_id(rows))


@router.post("/verified-boot-keys/import/row", dependencies=_admin_dependencies())
async def import_verified_boot_key_csv_row(
    request: Request,
    default_os_id: str | None = Query(
        None, description="os_id to use if the row omits the os_id column"
    ),
    store: ConfigStore = Depends(get_store),
) -> ImportResult:
    """Insert a single verified-boot-key record from a raw CSV body: a
    header line (`os_id,device,release,verified_boot_key_sha256` — `os_id`
    may be dropped if `default_os_id` is given) followed by exactly one
    data row."""
    body = (await request.body()).decode("utf-8-sig").strip()
    if not body:
        raise HTTPException(400, "Empty request body")

    try:
        rows = parse_csv_rows(body, default_os_id=default_os_id)
    except ConfigValidationError as e:
        raise HTTPException(400, str(e))
    if len(rows) != 1:
        raise HTTPException(400, f"Expected exactly 1 data row, got {len(rows)}")
    return await _insert_grouped(store, group_by_os_id(rows))
