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


class VerifyResult(BaseModel):
    verdict: Literal["pass", "fail"]
    reasons: list[str]
    os_id: str | None = None
    verified_boot_state: str | None = None
    device_locked: bool | None = None
    os_patch_level: int | None = None
    security_level: str | None = None
    # short-lived signed token a relying party can check, only set on pass
    token: str | None = None
