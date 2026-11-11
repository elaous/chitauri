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
    # Optional; echoed as requestDetails.requestPackageName, not verified.
    request_package_name: str | None = None


class RequestDetails(BaseModel):
    requestPackageName: str | None = None
    timestampMillis: str
    nonce: str


class AppIntegrity(BaseModel):
    # Always UNEVALUATED. Kept for Play Integrity parser compatibility.
    appRecognitionVerdict: Literal["UNEVALUATED"] = "UNEVALUATED"


class DeviceIntegrity(BaseModel):
    # Empty list means the device failed every check.
    deviceRecognitionVerdict: list[
        Literal["MEETS_DEVICE_INTEGRITY", "MEETS_STRONG_INTEGRITY"]
    ] = Field(default_factory=list)


class DeviceAttestationDetails(BaseModel):
    """Project extension: hardware and OS facts from Key Attestation."""

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
    # Set only on pass.
    token: str | None = None
