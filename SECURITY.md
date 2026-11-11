# Security Policy

graphene-attest verifies device integrity for relying parties (banks,
government services) that may make trust decisions based on its verdicts.
Treat any bypass of the verification logic, or any way to make the service
issue a `pass` verdict for a device/OS that shouldn't get one, as a
security vulnerability.

## Status

This project is an early-stage scaffold (see `README.md` → Status). It has
**not** been validated against real device attestation certificates and
should not be deployed in production yet. Please still report issues you
find — they're valuable before the first real deployment, not just after.

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, use GitHub's private vulnerability reporting for this repository
(the "Report a vulnerability" button under the repo's Security tab, or
<https://github.com/elaous/chitauri/security/advisories/new>). If that isn't
available to you, open an issue asking the maintainer
([@elaous](https://github.com/elaous)) to contact you privately, without
describing the vulnerability itself.

Only the latest commit on `main` is supported.

Please include:

- A description of the vulnerability and its potential impact
- Steps to reproduce (a request/response pair, a crafted certificate, etc.)
- Any suggested fix, if you have one

We'll acknowledge reports as promptly as we can and keep you updated as the
issue is investigated and fixed. We don't currently run a paid bug bounty.

## Scope

In scope:
- `app/attestation.py`, `app/chain.py`, `app/revocation.py` — the
  verification logic itself
- `app/storage/` — the config/allowlist storage adapters
- `app/admin.py` and anything that can mutate the allowlist or policy
- Authentication/authorization of the admin import endpoints

Out of scope (for now, given the project's stated status):
- Missing production hardening that's already called out as a TODO in
  `README.md` or in the code (e.g. "pinned Google roots not loaded yet") —
  please still report these as regular issues, just not as a security
  report with an expectation of an urgent fix.
