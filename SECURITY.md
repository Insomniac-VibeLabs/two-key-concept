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

Ledger entries and the head are AES-256-GCM ciphertext. The data key is
wrapped by the principal key. The head also needs a witness signature.
Someone who steals only the principal key cannot mint a verifying head
while `witness.pem` is elsewhere. Someone who steals both keys can.

Code scanning is the CodeQL workflow in `.github/workflows/codeql.yml`.
