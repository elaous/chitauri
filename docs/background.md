# Background

## The problem

Google's Play Integrity API bundles two distinct properties into one
pass/fail signal:

1. Is the hardware genuine and unmodified (root of trust intact)?
2. Is the OS a Google-certified build?

GrapheneOS passes (1) but deliberately fails (2), since it isn't Google's
own OS — even though it re-signs the boot image with a user-controlled key
and its verified boot chain is intact. Banks and government apps that only
check the bundled signal end up blocking a hardened, security-audited OS
along with genuinely compromised devices.

## The fix

Android's hardware Key Attestation (not Play Integrity) exposes (1) on its
own, independent of OS vendor, via a certificate extension baked into every
device with a TEE/StrongBox. This project separates the two properties back
out: verify the hardware claim directly, and check the OS build against an
allowlist of known-good signing keys — a list this project maintains
instead of trusting only Google's own certification.

## Key fields (see `app/attestation.py`)

- `verifiedBootState`: `Verified` (Google-signed) / `SelfSigned` (relocked
  with a user key — the normal state for GrapheneOS) / `Unverified` /
  `Failed`
- `deviceLocked`: bootloader locked or not — must be `true`
- `verifiedBootKey`: hash of whichever key signed the current boot image —
  must match a known GrapheneOS (or other supported OS) release key
- `verifiedBootHash`: hash of the actual boot image — cross-check against
  GrapheneOS's published reproducible build hashes

## Legal context (Brazil)

This project doesn't take a legal position. There's a plausible argument
that Lei 14.129/2021 (Governo Digital)'s interoperability and technology
neutrality principles, and the Marco Civil's open-access principles, weigh
against banking/gov apps hard-blocking non-Google-certified OSes — but as
of this writing there's no known enforcement action, ANPD/Procon ruling, or
court decision applying those laws to this specific situation. Treat this
as a policy argument to make to regulators or banks, not settled law. Get a
lawyer's read before relying on it.
