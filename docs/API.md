# API reference

Full machine-readable schema: [`docs/openapi.json`](./openapi.json)
(regenerate with `uv run python scripts/export_openapi.py`), or browse the
live docs at `/docs` (Swagger UI) / `/redoc` once the server is running.

## Why the response looks like Play Integrity

`POST /verify`'s response is deliberately shaped to resemble Google's
[Play Integrity decoded verdict token](https://developer.android.com/google/play/integrity/verdict)
— `requestDetails` / `appIntegrity` / `deviceIntegrity` — so that a relying
party migrating off (or alongside) Play Integrity can reuse most of its
existing response-parsing code. Where this API checks something Play
Integrity doesn't expose (verified boot key, OS patch level, etc.), those
facts live in a `deviceAttestation` extension object instead of being
shoehorned into the Play Integrity fields.

This is **not** a drop-in replacement for the Play Integrity *decryption*
step (Play Integrity returns an encrypted/signed JWT you decrypt with
Google-issued keys; this API returns plain JSON, optionally with its own
signed `token` once that's implemented — see the Roadmap in `README.md`).
It's the decoded *shape* that matches.

## Endpoints

### `POST /nonce`

Issues a single-use nonce to use as the attestation challenge.

```json
{ "nonce": "rjq9i8I0grvn40X4Et2XQlDzMAbn2wt6" }
```

### `POST /verify`

Request:

```json
{
  "nonce": "rjq9i8I0grvn40X4Et2XQlDzMAbn2wt6",
  "claimed_os": "grapheneos",
  "cert_chain_b64": ["<base64 DER leaf cert>", "<...intermediate...>", "<...root...>"],
  "request_package_name": "com.example.bank"
}
```

`request_package_name` is optional and purely echoed back in the response
for Play-Integrity-shaped parsers that expect the field to exist — this
service doesn't itself attest app identity.

Response (pass):

```json
{
  "requestDetails": {
    "requestPackageName": "com.example.bank",
    "timestampMillis": "1777000000000",
    "nonce": "rjq9i8I0grvn40X4Et2XQlDzMAbn2wt6"
  },
  "appIntegrity": { "appRecognitionVerdict": "UNEVALUATED" },
  "deviceIntegrity": {
    "deviceRecognitionVerdict": ["MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"]
  },
  "deviceAttestation": {
    "os_id": "grapheneos",
    "verdict": "pass",
    "reasons": [],
    "verified_boot_state": "SelfSigned",
    "device_locked": true,
    "os_patch_level": 20260901,
    "security_level": "StrongBox"
  },
  "token": null
}
```

Response (fail) — `deviceIntegrity.deviceRecognitionVerdict` is empty and
`deviceAttestation.reasons` explains why:

```json
{
  "requestDetails": { "requestPackageName": null, "timestampMillis": "1777000000000", "nonce": "..." },
  "appIntegrity": { "appRecognitionVerdict": "UNEVALUATED" },
  "deviceIntegrity": { "deviceRecognitionVerdict": [] },
  "deviceAttestation": {
    "os_id": "grapheneos",
    "verdict": "fail",
    "reasons": ["Bootloader is not locked"],
    "verified_boot_state": "SelfSigned",
    "device_locked": false,
    "os_patch_level": 20260901,
    "security_level": "StrongBox"
  },
  "token": null
}
```

`deviceRecognitionVerdict` values map onto hardware Key Attestation as:

| Value | Meaning here |
|---|---|
| `MEETS_DEVICE_INTEGRITY` | Verified boot chain intact, signed by an allowlisted OS key |
| `MEETS_STRONG_INTEGRITY` | Also backed by StrongBox, not just a TEE |
| *(empty list)* | Failed one or more checks — see `deviceAttestation.reasons` |

## Importing allowlist data

The allowlist (`verified_boot_keys`, one row per OS + device + release) can
be populated four ways — see `app/admin.py`. All admin endpoints require an
`X-Admin-Api-Key` header matching the `ADMIN_API_KEY` env var; the admin API
is disabled (503) if that's unset.

| Endpoint | Shape | Use for |
|---|---|---|
| `POST /admin/verified-boot-keys` | single JSON object | adding one key |
| `POST /admin/verified-boot-keys/bulk` | JSON array | adding many keys at once |
| `POST /admin/verified-boot-keys/import` | multipart CSV file | bulk-importing from a spreadsheet export |
| `POST /admin/verified-boot-keys/import/row` | raw CSV body (header + 1 row) | adding one key from a CSV-shaped source |

JSON shape (single or array elements):

```json
{
  "os_id": "grapheneos",
  "device": "Pixel 8",
  "release": "2026.09.01",
  "verified_boot_key_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```

CSV columns: `os_id,device,release,verified_boot_key_sha256`. `os_id` can be
omitted from the file if every row is for the same OS — pass
`?default_os_id=grapheneos` on the request instead.

```
os_id,device,release,verified_boot_key_sha256
grapheneos,Pixel 8,2026.09.01,e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85
grapheneos,Pixel 9,2026.09.01,2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
```

```bash
curl -X POST http://localhost:8000/admin/verified-boot-keys/import \
  -H "X-Admin-Api-Key: $ADMIN_API_KEY" \
  -F file=@keys.csv
```

Every import path de-duplicates by `verified_boot_key_sha256` within the
target `os_id` and returns how many of the submitted rows were actually new:

```json
{ "received": 2, "added": 1, "by_os_id": { "grapheneos": 1 } }
```

There's also a CLI for operators with direct DB/AWS access who'd rather
skip the HTTP API — `uv run python scripts/import_verified_boot_keys.py --help`.

Every `/admin/verified-boot-keys*` call writes `os_id`s only after first
confirming *every* `os_id` in the batch already exists — a batch covering
one known and one unknown `os_id` fails the whole request with no partial
write, rather than silently persisting the known one.

## Rate limiting

All endpoints are rate-limited per client IP via
[slowapi](https://github.com/laurentS/slowapi) (`app/rate_limit.py`).
Exceeding a limit returns `429 Too Many Requests`. Defaults (overridable via
env vars, see `app/settings.py`):

| Endpoint(s) | Setting | Default |
|---|---|---|
| `POST /nonce` | `RATE_LIMIT_NONCE` | `20/minute` |
| `POST /verify` | `RATE_LIMIT_VERIFY` | `20/minute` |
| `POST /admin/*` (all five, shared) | `RATE_LIMIT_ADMIN` | `30/minute` |

`/nonce` and `/verify` are public and unauthenticated, so this is the main
abuse control for them. `/admin/*` is already gated by `ADMIN_API_KEY`, but
is rate-limited too as defense in depth against a leaked or guessed key —
notably, the limit is enforced via a dependency that always runs *before*
the API-key check (`app/rate_limit.py`'s `enforce()`, not the usual
`@limiter.limit` decorator), so repeated wrong-key attempts count against
the limit instead of being rejected for free.

## Storage backends

Config (OS profiles, verified boot keys, policy) is read/written through
the `ConfigStore` interface (`app/storage/base.py`), with two adapters:

- **Postgres** (default) — `app/storage/postgres_store.py`, via SQLAlchemy.
  Schema managed by Alembic (`migrations/`).
- **DynamoDB** — `app/storage/dynamodb_store.py`, via boto3. Tables created
  by `scripts/create_dynamodb_tables.py`.

Select with the `STORAGE_BACKEND` env var (`postgres` or `dynamodb`); see
`app/settings.py` for the rest of the backend-specific settings
(`DATABASE_URL`, `DYNAMODB_TABLE_PREFIX`, `DYNAMODB_REGION`,
`DYNAMODB_ENDPOINT_URL` for local testing against DynamoDB Local).

Both adapters do a read-then-write for de-duplicating bulk key inserts;
under concurrent writers to the *same* `os_id` this can under-count
`added`/lose a racing insert. Fine for the low-frequency, largely
single-operator way this config is expected to change — worth revisiting
with a conditional write (Postgres: unique constraint + `ON CONFLICT`;
DynamoDB: a conditional `update_item`) before using this as a
high-concurrency control plane.
