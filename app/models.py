from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class NonceResponse(BaseModel):
    nonce: str  # base64url, use directly as the attestation challenge


class VerifyRequest(BaseModel):
    nonce: str
    claimed_os: str = Field(description="e.g. 'grapheneos' or 'stock_android'")
    # DER-encoded X.509 certs, base64, leaf-first
    cert_chain_b64: list[str]
    # Optional, echoed back in requestDetails.requestPackageName — this
    # service doesn't itself check app identity, but relying parties
    # migrating from Play Integrity often want it round-tripped.
    request_package_name: str | None = None


# --- Response shape ---
#
# Shaped to match Google's Play Integrity decoded verdict token
# (https://developer.android.com/google/play/integrity/verdict) so a relying
# party migrating off Play Integrity can reuse most of its existing parsing
# code. `deviceAttestation` is this project's own extension carrying the
# hardware/OS facts Play Integrity doesn't expose.


class RequestDetails(BaseModel):
    requestPackageName: str | None = None
    timestampMillis: str
    nonce: str


class AppIntegrity(BaseModel):
    # This service doesn't attest app identity/licensing (no Play Store
    # involved), so this is always UNEVALUATED — kept only for shape
    # compatibility with Play Integrity response parsers.
    appRecognitionVerdict: Literal["UNEVALUATED"] = "UNEVALUATED"


class DeviceIntegrity(BaseModel):
    # Subset of Play Integrity's verdicts that map onto hardware Key
    # Attestation: MEETS_DEVICE_INTEGRITY (verified boot chain intact, on an
    # allowlisted OS key) and MEETS_STRONG_INTEGRITY (backed by StrongBox,
    # not just a TEE). Empty means the device failed every check.
    deviceRecognitionVerdict: list[
        Literal["MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"]
    ] = Field(default_factory=list)


class DeviceAttestationDetails(BaseModel):
    """Extension beyond the Play Integrity shape: the hardware/OS facts this
    project checks directly from the Key Attestation certificate."""

    os_id: str | None = None
    verdict: Literal["pass", "fail"]
    reasons: list[str] = Field(default_factory=list)
    verified_boot_state: str | None = None
    device_locked: bool | None = None
    os_patch_level: int | None = None
    security_level: str | None = None


class VerifyResult(BaseModel):
    requestDetails: RequestDetails
    appIntegrity: AppIntegrity
    deviceIntegrity: DeviceIntegrity
    deviceAttestation: DeviceAttestationDetails
    # short-lived signed token a relying party can check, only set on pass
    token: str | None = None
