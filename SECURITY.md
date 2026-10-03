# Security

This is a prototype. Report vulnerabilities privately to the repository
admins of Insomniac-VibeLabs. Do not open a public issue for an unfixed
security bug.

## In scope

- Fail-open on either path (a deny or a missing ballot must not become allow)
- Token replay, argument substitution, or redemption after revocation
- Ledger tampering that still verifies
- Judge credential sent to a redirected host
- Agent proposal that causes tool execution inside `authorize_from_agent`

## Out of scope for this repository

- Malware or DLP scanning of tool payloads. That lives in `two-key` and is
  intentionally absent here.
- FIPS validation. Algorithms are Ed25519 and SHA-256 from `cryptography`.

The ledger file is integrity-protected by the principal signature. It is not
encrypted. Anyone who can read the directory can read the entries.
