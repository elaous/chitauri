# chitauri

An OS-neutral device integrity attestation API built on Android hardware key attestation.

An open-source service — the missing piece between Android's hardware Key
Attestation and apps (banks, government services) that currently only trust Google's Play Integrity API.

It verifies hardware-signed attestation certificates directly from the
device's TEE/StrongBox, and checks the boot state against a maintained
allowlist of known-good OS signing keys — starting with GrapheneOS, extensible
to any other AOSP-based OS that publishes its verified-boot key fingerprints
(CalyxOS, LineageOS, /e/OS, etc).

This does **not** use Play Integrity, Play Services, or any Google account.
It uses the hardware attestation capability built into the Android Keystore,
which works identically regardless of which OS is installed.

## Why this exists

Play Integrity's `ctsProfileMatch`/`MEETS_DEVICE_INTEGRITY` checks fail on
any OS that isn't a Google-certified build — including OSes that are hardened
and security-audited, like GrapheneOS. This forces users of alternative OSes
out of banking and government apps even when their device's hardware root of
trust is fully intact and verifiable. See the project docs (`docs/background.md`)
for the technical and legal background.

## Architecture

```
Device (GrapheneOS) --attestation cert chain--> API /verify --> Play-Integrity-shaped
                                                    |           JSON verdict (token: null)
                                                    +-- allowlist of known
                                                    |   verifiedBootKey hashes
                                                    |   (config store, seeded from
                                                    |   config/allowlist.yaml)
                                                    +-- Google's hardware root
                                                        certs (pinned; list is empty
                                                        today, see Status)

Not yet wired into /verify: Google's revocation list
(https://android.googleapis.com/attestation/status, fetched and cached
by app/revocation.py).
```

Flow:
1. Client requests a single-use nonce (valid 5 minutes, held in process
   memory): `POST /nonce`
2. Client generates an attestation key with that nonce as the challenge,
   via Android Keystore, and sends the resulting cert chain: `POST /verify`
3. Server:
   - Validates the chain signatures and that the root matches a pinned
     Google hardware attestation root (the pinned list is currently empty,
     so this check always fails)
   - Parses the attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`)
   - Confirms `deviceLocked == true`
   - Confirms `verifiedBootKey` hash is in the allowlist for the claimed OS
   - Confirms `verifiedBootState` matches what's expected for that OS
     (`SelfSigned` for GrapheneOS re-signed with a user key, `Verified` for
     stock/Google-certified builds)
   - Confirms the attestation challenge equals the issued nonce
   - Returns a Play-Integrity-shaped JSON verdict (`pass` or `fail` with
     reasons); the `token` field is always `null` because signed verdict
     tokens are not implemented yet

Not implemented yet: revocation-list checking in `/verify`, the
`max_patch_age_days` patch-level policy, and signed verdict tokens. The
`min_security_level` policy is only partly enforced (software-backed
attestation is rejected; the TEE/StrongBox distinction is not).

## Status

Early scaffold. The pinned Google root list in `app/main.py` is empty, so
`/verify` currently reports a chain failure for every request. The ASN.1 parsing in `app/attestation.py` implements the
fields documented at
https://source.android.com/docs/security/keystore/attestation — but has
**not yet been validated against real device output**. Google's own
reference implementation (Apache-2.0, Java/Bouncy Castle) lives at
https://github.com/google/android-key-attestation and its successor
https://github.com/android/keyattestation — treat that as the source of
truth if this Python port disagrees with it. GrapheneOS's own
[Auditor](https://github.com/GrapheneOS/Auditor) /
[AttestationServer](https://github.com/GrapheneOS/AttestationServer) are
the closest prior art, though built for device-pairing, not a third-party
relying-party API.

**Do not deploy this in production until it has been tested against real
attestation certificates from real GrapheneOS devices.**

## Setup

Dependencies are managed with [uv](https://docs.astral.sh/uv/) and config
(the OS allowlist + policy) lives in Postgres (default) or DynamoDB instead
of a flat file.

Python 3.11+ is required. The service is a plain Python/FastAPI app and
runs on any OS with Python and uv; the Postgres container needs Docker.

```bash
# install uv if you don't have it: https://docs.astral.sh/uv/getting-started/installation/
uv sync

# start a local Postgres (or point DATABASE_URL at one you already run)
docker compose up -d postgres

# apply schema migrations
uv run alembic upgrade head

# bootstrap the DB from config/allowlist.yaml (safe to re-run)
uv run python scripts/seed_config.py

uv run uvicorn app.main:app --reload
```

By default the app connects to
`postgresql+asyncpg://graphene_attest:graphene_attest@localhost:5432/graphene_attest`
(matching `docker-compose.yml`). Override with a `DATABASE_URL` env var or a
`.env` file, e.g. `DATABASE_URL=postgresql+asyncpg://user:pass@host:5432/db`.

### Running tests

```bash
uv sync --group dev
uv run pytest -q
uv run ruff check .
```

Postgres-backed tests are skipped when no database is reachable; start one
with `docker compose up -d postgres` to run them.

### Configuration

Settings are read from environment variables or a `.env` file
(see `app/settings.py`):

| Variable | Default | Purpose |
| --- | --- | --- |
| `STORAGE_BACKEND` | `postgres` | `postgres` or `dynamodb` |
| `DATABASE_URL` | local docker-compose Postgres | Postgres connection string |
| `ADMIN_API_KEY` | unset | Enables `/admin/*` endpoints when set (sent as the `X-Admin-Api-Key` header). It MUST be a long random value in any shared deployment. |
| `ADMIN_IMPORT_MAX_ROWS`, `ADMIN_IMPORT_MAX_FILE_BYTES` | `10000`, `10000000` | Limits for admin bulk and CSV imports |
| `RATE_LIMIT_NONCE`, `RATE_LIMIT_VERIFY`, `RATE_LIMIT_ADMIN` | `20/minute`, `20/minute`, `30/minute` | Per-client-IP rate limits |
| `DYNAMODB_TABLE_PREFIX`, `DYNAMODB_REGION`, `DYNAMODB_ENDPOINT_URL` | `graphene_attest_`, unset, unset | DynamoDB backend only |

The default database credentials in `docker-compose.yml` are for local
development only and MUST NOT be used in a deployment.

Full API reference (including the admin import endpoints and the
DynamoDB alternative backend): [`docs/API.md`](docs/API.md). Machine-readable
schema: [`docs/openapi.json`](docs/openapi.json), or `/docs` on a running
server.

## Populating the allowlist

The OS allowlist (`os_profiles` + `verified_boot_keys` tables) needs real
`verifiedBootKey` SHA-256 hashes, one row per supported OS + device +
release. GrapheneOS publishes signing key fingerprints for each release;
there is no public API for this today, so maintaining it will initially be
a manual/scripted process against their release notes and repo. This is the
main ongoing maintenance burden of running this service — see
`docs/background.md`.

`config/allowlist.yaml` ships with the `grapheneos` and `stock_android` OS
profiles and no keys; until keys are added, every verdict fails with an
empty-allowlist reason. It is kept as human-editable seed data — edit it and
re-run `uv run python scripts/seed_config.py` to sync it into the configured
backend. For adding keys afterward (e.g. a new GrapheneOS release) without
touching the YAML file, see **Importing allowlist data** in
[`docs/API.md`](docs/API.md) for the admin JSON/CSV import endpoints and CLI.

## Roadmap

- [ ] Validate ASN.1 parsing against real attestation samples (needs a real
      GrapheneOS device to generate test vectors)
- [ ] Share the nonce store across processes (currently in-memory)
- [ ] Automate allowlist updates from GrapheneOS release metadata
- [ ] Wire the revocation list check (`app/revocation.py`) into `/verify`
- [ ] Load the pinned Google hardware attestation roots
- [ ] Enforce the patch-level and minimum-security-level policies
- [ ] Issue signed verdict tokens
- [ ] Add policy engine (risk tiers instead of binary pass/fail)
- [ ] Support additional OSes (CalyxOS, LineageOS+microG)
- [ ] Client-side sample (Android) showing how to request a nonce and
      generate the attestation key
- [ ] Threat model doc: replay, key extraction, downgrade attacks

## Contributing

Issues and pull requests are welcome. See `CONTRIBUTING.md` for development setup and `CODE_OF_CONDUCT.md` for
community guidelines. Found a security issue? See `SECURITY.md` instead of
opening a public issue.

## License

Apache License 2.0 — see `LICENSE` and `NOTICE`. Apache-2.0 was chosen over
MIT/BSD specifically so that device OEMs and OS vendors (GrapheneOS,
Motorola, etc.) adopting or extending this service get an explicit patent
grant alongside the copyright license.
