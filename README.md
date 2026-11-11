# graphene-attest

An open-source, OS-neutral device integrity attestation API — the missing
piece between Android's hardware Key Attestation and apps (banks, government
services) that currently only trust Google's Play Integrity API.

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
Device (GrapheneOS) --attestation cert chain--> API /verify --> signed verdict token
                                                    |
                                                    +-- allowlist of known
                                                    |   verifiedBootKey hashes
                                                    |   (config/allowlist.yaml)
                                                    +-- Google's hardware root
                                                    |   certs (pinned)
                                                    +-- Google's revocation
                                                        list (synced, cached)
                                                        https://android.googleapis.com/attestation/status
```

Flow:
1. Client requests a nonce: `POST /nonce`
2. Client generates an attestation key with that nonce as the challenge,
   via Android Keystore, and sends the resulting cert chain: `POST /verify`
3. Server:
   - Validates the chain up to Google's hardware attestation root
   - Checks the leaf key isn't in Google's revocation list
   - Parses the attestation extension (OID `1.3.6.1.4.1.11129.2.1.17`)
   - Confirms `deviceLocked == true`
   - Confirms `verifiedBootKey` hash is in the allowlist for the claimed OS
   - Confirms `verifiedBootState` matches what's expected for that OS
     (`SelfSigned` for GrapheneOS re-signed with a user key, `Verified` for
     stock/Google-certified builds)
   - Confirms patch level is recent enough (policy-configurable)
   - Issues a short-lived signed verdict token the relying party (bank, gov
     app) can check

## Status

Early scaffold. The ASN.1 parsing in `app/attestation.py` implements the
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
(the OS allowlist + policy) lives in Postgres instead of a flat file.

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
| `ADMIN_API_KEY` | unset | Enables `/admin/*` endpoints when set. It MUST be a long random value in any shared deployment. |
| `RATE_LIMIT_NONCE`, `RATE_LIMIT_VERIFY`, `RATE_LIMIT_ADMIN` | `20/minute`, `20/minute`, `30/minute` | Per-client-IP rate limits |
| `DYNAMODB_TABLE_PREFIX`, `DYNAMODB_REGION`, `DYNAMODB_ENDPOINT_URL` | see `app/settings.py` | DynamoDB backend only |

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

`config/allowlist.yaml` is kept as human-editable seed data — edit it and
re-run `uv run python scripts/seed_config.py` to sync it into the configured
backend. For adding keys afterward (e.g. a new GrapheneOS release) without
touching the YAML file, see **Importing allowlist data** in
[`docs/API.md`](docs/API.md) for the admin JSON/CSV import endpoints and CLI.

## Roadmap

- [ ] Validate ASN.1 parsing against real attestation samples (needs a real
      GrapheneOS device to generate test vectors)
- [ ] Automate allowlist updates from GrapheneOS release metadata
- [ ] Add revocation list caching/sync job
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
