"""
Validates a certificate chain up to Google's hardware attestation root.

STATUS: stub. A production version needs:
  - Google's pinned hardware attestation root cert(s), fetched once from
    https://developer.android.com/training/articles/security-key-attestation#root_certificate
    and pinned in this repo (do not fetch them live on every request)
  - signature verification at each link in the chain (leaf -> intermediate(s) -> root)
  - revocation checking of every certificate in the chain (see revocation.py),
    not just the leaf
  - basic X.509 validity checks (notBefore/notAfter, path length constraints)

`cryptography` doesn't ship a full path-validation engine out of the box;
consider using `pyca/cryptography`'s primitives for signature checks plus a
small hand-rolled path walk (this is a narrow, well-defined chain — 3-4
certs, not general web PKI), or wrapping OpenSSL via subprocess/openssl
verify with the pinned root as trust anchor for a first pass.
"""
from __future__ import annotations

from dataclasses import dataclass

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa


@dataclass
class ChainValidationResult:
    valid: bool
    reasons: list[str]


def _verify_signed_by(child: x509.Certificate, parent: x509.Certificate) -> bool:
    pub = parent.public_key()
    try:
        if isinstance(pub, rsa.RSAPublicKey):
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                padding.PKCS1v15(),
                child.signature_hash_algorithm,
            )
        elif isinstance(pub, ec.EllipticCurvePublicKey):
            pub.verify(
                child.signature,
                child.tbs_certificate_bytes,
                ec.ECDSA(child.signature_hash_algorithm),
            )
        else:
            return False
        return True
    except Exception:
        return False


def validate_chain(
    certs: list[x509.Certificate], pinned_roots: list[x509.Certificate]
) -> ChainValidationResult:
    """certs must be ordered leaf-first. Extremely minimal: checks each cert
    is signed by the next one up, and the final cert matches a pinned root.
    Does NOT yet check validity periods, revocation, or path constraints —
    add those before relying on this."""
    reasons: list[str] = []

    if len(certs) < 2:
        return ChainValidationResult(False, ["Chain too short"])

    for child, parent in zip(certs, certs[1:]):
        if not _verify_signed_by(child, parent):
            reasons.append(
                f"Signature check failed: {child.subject} not signed by {parent.subject}"
            )

    root = certs[-1]
    if not any(root.public_key().public_numbers() == r.public_key().public_numbers() for r in pinned_roots):
        reasons.append("Chain does not terminate in a pinned Google hardware root")

    return ChainValidationResult(valid=not reasons, reasons=reasons)
