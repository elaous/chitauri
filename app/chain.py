"""Certificate chain validation. Stub: no validity, revocation or path checks."""
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
    """Certs leaf-first. Checks signatures and root pin only."""
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
