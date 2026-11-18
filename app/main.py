from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import threading
import time

from cryptography import x509
from fastapi import Depends, FastAPI, HTTPException, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware

from app.admin import router as admin_router
from app.attestation import AttestationParseError, SecurityLevel, parse_leaf_certificate
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

# In-memory nonce store: single process only.
_issued_nonces: dict[str, float] = {}
_nonce_lock = threading.Lock()
_NONCE_TTL_SECONDS = 300
_MAX_OUTSTANDING_NONCES = 10_000

MAX_CERT_CHAIN_LENGTH = 6
MAX_CERT_B64_LENGTH = 8192

DEFAULT_MIN_SECURITY_LEVEL = "TrustedEnvironment"
_SECURITY_LEVEL_RANKS = {name: rank for rank, name in SecurityLevel.NAMES.items()}

logger = logging.getLogger(__name__)

PINNED_GOOGLE_ROOTS: list[x509.Certificate] = []


@app.post("/nonce", response_model=NonceResponse)
@limiter.limit(settings.rate_limit_nonce)
def issue_nonce(request: Request) -> NonceResponse:
    nonce = secrets.token_urlsafe(24)
    _register_nonce(nonce)
    return NonceResponse(nonce=nonce)


def _register_nonce(nonce: str) -> None:
    with _nonce_lock:
        _purge_expired_nonces()
        while len(_issued_nonces) >= _MAX_OUTSTANDING_NONCES:
            _issued_nonces.pop(next(iter(_issued_nonces)), None)
        _issued_nonces[nonce] = time.time()


def _purge_expired_nonces() -> None:
    cutoff = time.time() - _NONCE_TTL_SECONDS
    for nonce in [n for n, issued_at in _issued_nonces.items() if issued_at < cutoff]:
        _issued_nonces.pop(nonce, None)


def _security_level_too_low(level: int, minimum_name: str) -> bool:
    minimum_rank = _SECURITY_LEVEL_RANKS.get(minimum_name)
    if minimum_rank is None or level not in SecurityLevel.NAMES:
        return True
    return level < minimum_rank


def _consume_nonce(nonce: str) -> bool:
    with _nonce_lock:
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

    if len(req.cert_chain_b64) > MAX_CERT_CHAIN_LENGTH:
        raise HTTPException(400, "Certificate chain too long")
    if any(len(c) > MAX_CERT_B64_LENGTH for c in req.cert_chain_b64):
        raise HTTPException(400, "Certificate too large")

    try:
        der_certs = [base64.b64decode(c, validate=True) for c in req.cert_chain_b64]
        certs = [x509.load_der_x509_certificate(c) for c in der_certs]
    except Exception as e:
        logger.warning("Rejected malformed certificate chain: %s", type(e).__name__)
        raise HTTPException(400, "Invalid certificate chain") from e

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
    min_security_level = policy.get("min_security_level", DEFAULT_MIN_SECURITY_LEVEL)
    if _security_level_too_low(parsed.attestation_security_level, min_security_level):
        reasons.append(f"Security level too low: {parsed.security_level_name}")

    if profile.require_device_locked and parsed.device_locked is not True:
        reasons.append("Bootloader is not locked")

    if parsed.verified_boot_state_name != profile.expected_verified_boot_state:
        reasons.append(
            f"Unexpected verifiedBootState for {profile.display_name}: "
            f"got {parsed.verified_boot_state_name}, "
            f"expected {profile.expected_verified_boot_state}"
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
        token=None,
    )
