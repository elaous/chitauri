from __future__ import annotations

import base64
import secrets
import time

from cryptography import x509
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.attestation import AttestationParseError, parse_leaf_certificate
from app.chain import validate_chain
from app.config import get_os_profile, get_policy
from app.db import get_session
from app.models import NonceResponse, VerifyRequest, VerifyResult

app = FastAPI(title="graphene-attest", version="0.1.0")

# In-memory nonce store for this scaffold. Replace with Redis/DB + short TTL
# and single-use enforcement before running more than one server process.
_issued_nonces: dict[str, float] = {}
_NONCE_TTL_SECONDS = 300

PINNED_GOOGLE_ROOTS: list[x509.Certificate] = []  # TODO: load pinned root certs at startup


@app.post("/nonce", response_model=NonceResponse)
def issue_nonce() -> NonceResponse:
    nonce = secrets.token_urlsafe(24)
    _issued_nonces[nonce] = time.time()
    return NonceResponse(nonce=nonce)


def _consume_nonce(nonce: str) -> bool:
    issued_at = _issued_nonces.pop(nonce, None)
    if issued_at is None:
        return False
    return (time.time() - issued_at) <= _NONCE_TTL_SECONDS


@app.post("/verify", response_model=VerifyResult)
async def verify(req: VerifyRequest, db: AsyncSession = Depends(get_session)) -> VerifyResult:
    reasons: list[str] = []

    if not _consume_nonce(req.nonce):
        raise HTTPException(400, "Unknown or expired nonce")

    profile = await get_os_profile(db, req.claimed_os)
    if profile is None:
        raise HTTPException(400, f"Unknown claimed_os '{req.claimed_os}'")

    try:
        der_certs = [base64.b64decode(c) for c in req.cert_chain_b64]
        certs = [x509.load_der_x509_certificate(c) for c in der_certs]
    except Exception as e:
        raise HTTPException(400, f"Invalid certificate chain: {e}")

    chain_result = validate_chain(certs, PINNED_GOOGLE_ROOTS)
    if not chain_result.valid:
        reasons.extend(chain_result.reasons)

    try:
        parsed = parse_leaf_certificate(der_certs[0])
    except AttestationParseError as e:
        return VerifyResult(verdict="fail", reasons=[str(e)])

    if parsed.challenge.decode(errors="replace") != req.nonce:
        reasons.append("Attestation challenge does not match issued nonce")

    policy = await get_policy(db)
    if parsed.security_level_name != policy.get("min_security_level", "TrustedEnvironment") and (
        parsed.attestation_security_level < 1
    ):
        reasons.append(f"Security level too low: {parsed.security_level_name}")

    if parsed.device_locked is not True:
        reasons.append("Bootloader is not locked")

    expected_state = profile["expected_verified_boot_state"]
    if parsed.verified_boot_state_name != expected_state:
        reasons.append(
            f"Unexpected verifiedBootState for {profile['display_name']}: "
            f"got {parsed.verified_boot_state_name}, expected {expected_state}"
        )

    known_keys = {
        entry["verified_boot_key_sha256"] for entry in profile.get("verified_boot_keys", [])
    }
    if parsed.verified_boot_key is not None:
        import hashlib

        key_hash = hashlib.sha256(parsed.verified_boot_key).hexdigest()
        if known_keys and key_hash not in known_keys:
            reasons.append(
                f"verifiedBootKey hash {key_hash} not in allowlist for {profile['display_name']}"
            )
        elif not known_keys:
            reasons.append(
                "Allowlist for this OS is empty — populate config/allowlist.yaml "
                "before trusting any verdict"
            )
    else:
        reasons.append("No rootOfTrust present in attestation — cannot verify boot state")

    verdict: VerifyResult = VerifyResult(
        verdict="fail" if reasons else "pass",
        reasons=reasons,
        os_id=req.claimed_os,
        verified_boot_state=parsed.verified_boot_state_name,
        device_locked=parsed.device_locked,
        os_patch_level=parsed.os_patch_level,
        security_level=parsed.security_level_name,
        token=None,  # TODO: issue a signed JWT/PASETO here on pass
    )
    return verdict
