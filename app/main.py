from __future__ import annotations

import base64
import hashlib
import secrets
import time

from cryptography import x509
from fastapi import Depends, FastAPI, HTTPException, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.admin import router as admin_router
from app.attestation import AttestationParseError, parse_leaf_certificate
from app.chain import validate_chain
from app.models import (
    AppIntegrity,
    DeviceAttestationDetails,
    DeviceIntegrity,
    NonceResponse,
    RequestDetails,
    VerifyRequest,
    VerifyResult,
)
from app.rate_limit import limiter
from app.settings import settings
from app.storage import ConfigStore, get_store

app = FastAPI(
    title="graphene-attest",
    version="0.1.0",
    description=(
        "An open-source, OS-neutral device integrity attestation API. "
        "Response shape mirrors Google's Play Integrity decoded verdict "
        "token where possible — see docs/API.md."
    ),
    license_info={
        "name": "Apache-2.0",
        "url": "https://www.apache.org/licenses/LICENSE-2.0",
    },
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)
app.include_router(admin_router)

# In-memory nonce store for this scaffold. Replace with Redis/DB + short TTL
# and single-use enforcement before running more than one server process.
_issued_nonces: dict[str, float] = {}
_NONCE_TTL_SECONDS = 300

PINNED_GOOGLE_ROOTS: list[x509.Certificate] = []  # TODO: load pinned root certs at startup


@app.post("/nonce", response_model=NonceResponse)
@limiter.limit(settings.rate_limit_nonce)
def issue_nonce(request: Request) -> NonceResponse:
    nonce = secrets.token_urlsafe(24)
    _issued_nonces[nonce] = time.time()
    return NonceResponse(nonce=nonce)


def _consume_nonce(nonce: str) -> bool:
    issued_at = _issued_nonces.pop(nonce, None)
    if issued_at is None:
        return False
    return (time.time() - issued_at) <= _NONCE_TTL_SECONDS


def _device_recognition_verdict(
    *, reasons: list[str], security_level: str | None
) -> list[str]:
    if reasons:
        return []
    verdict = ["MEETS_DEVICE_INTEGRITY"]
    if security_level == "StrongBox":
        verdict.append("MEETS_STRONG_INTEGRITY")
    return verdict


@app.post("/verify", response_model=VerifyResult)
@limiter.limit(settings.rate_limit_verify)
async def verify(
    request: Request, req: VerifyRequest, store: ConfigStore = Depends(get_store)
) -> VerifyResult:
    reasons: list[str] = []
    request_details = RequestDetails(
        requestPackageName=req.request_package_name,
        timestampMillis=str(int(time.time() * 1000)),
        nonce=req.nonce,
    )

    if not _consume_nonce(req.nonce):
        raise HTTPException(400, "Unknown or expired nonce")

    profile = await store.get_os_profile(req.claimed_os)
    if profile is None:
        raise HTTPException(400, f"Unknown claimed_os '{req.claimed_os}'")

    if not req.cert_chain_b64:
        raise HTTPException(400, "cert_chain_b64 must not be empty")

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
        return VerifyResult(
            requestDetails=request_details,
            appIntegrity=AppIntegrity(),
            deviceIntegrity=DeviceIntegrity(deviceRecognitionVerdict=[]),
            deviceAttestation=DeviceAttestationDetails(
                os_id=req.claimed_os, verdict="fail", reasons=[str(e)]
            ),
        )

    if parsed.challenge.decode(errors="replace") != req.nonce:
        reasons.append("Attestation challenge does not match issued nonce")

    policy = await store.get_policy()
    if parsed.security_level_name != policy.get("min_security_level", "TrustedEnvironment") and (
        parsed.attestation_security_level < 1
    ):
        reasons.append(f"Security level too low: {parsed.security_level_name}")

    if profile.require_device_locked and parsed.device_locked is not True:
        reasons.append("Bootloader is not locked")

    if parsed.verified_boot_state_name != profile.expected_verified_boot_state:
        reasons.append(
            f"Unexpected verifiedBootState for {profile.display_name}: "
            f"got {parsed.verified_boot_state_name}, expected {profile.expected_verified_boot_state}"
        )

    known_keys = {key.verified_boot_key_sha256 for key in profile.verified_boot_keys}
    if parsed.verified_boot_key is not None:
        key_hash = hashlib.sha256(parsed.verified_boot_key).hexdigest()
        if known_keys and key_hash not in known_keys:
            reasons.append(
                f"verifiedBootKey hash {key_hash} not in allowlist for {profile.display_name}"
            )
        elif not known_keys:
            reasons.append(
                f"Allowlist for {profile.display_name} is empty — populate it via "
                "the /admin/verified-boot-keys endpoints before trusting any verdict"
            )
    else:
        reasons.append("No rootOfTrust present in attestation — cannot verify boot state")

    device_integrity = DeviceIntegrity(
        deviceRecognitionVerdict=_device_recognition_verdict(
            reasons=reasons, security_level=parsed.security_level_name
        )
    )

    return VerifyResult(
        requestDetails=request_details,
        appIntegrity=AppIntegrity(),
        deviceIntegrity=device_integrity,
        deviceAttestation=DeviceAttestationDetails(
            os_id=req.claimed_os,
            verdict="fail" if reasons else "pass",
            reasons=reasons,
            verified_boot_state=parsed.verified_boot_state_name,
            device_locked=parsed.device_locked,
            os_patch_level=parsed.os_patch_level,
            security_level=parsed.security_level_name,
        ),
        token=None,  # TODO: issue a signed JWT/PASETO here on pass
    )
