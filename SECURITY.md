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
wrapped by a ledger key stored outside the ledger directory. The head needs
both the principal signature and a witness signature. The witness key is also
outside the ledger directory. Stealing only the principal key does not decrypt
the log and does not sign a new head. Stealing the ledger key decrypts.
Stealing the witness key as well allows a forged head.

A redemption intent is checkpointed before the tool runs. A later retry does
not run the tool. Concurrent calls are locked. A crash before the tool runs
blocks a retry; a tool exception does not.

Code scanning in CI is `.github/workflows/security.yml` (bandit). CodeQL is
`.github/workflows/codeql.yml` and runs only if GitHub Advanced Security is
enabled for this private repository.
