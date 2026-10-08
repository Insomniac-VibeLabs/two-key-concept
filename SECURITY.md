# Security

This is a prototype and a public concept. It has had no independent review and
has no production use. Security findings are welcome as public issues on this
repository: the project would rather have them seen and argued over than
hidden. State what the code does, what the docs claim, and how you checked.

Private vulnerability reporting (the repository's Security tab, "Report a
vulnerability") will become the channel once the product is more mature and in
use. This file will say so when that happens.

The threat model is [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md). This file
is how to report a vulnerability. It is not the model.

## In scope

- Fail-open on either path (a deny or a missing ballot must not become allow)
- Token replay, argument substitution, or redemption of a token issued before
  a revocation (`revoke` ends earlier tokens; it does not stop new approvals)
- Ledger tampering that still verifies
- Judge credential sent to a redirected host
- Agent proposal that causes tool execution inside `authorize_from_agent`
- A redeeming gateway that can mint a token it will accept
- A judge that is the monitored agent being accepted at start-up: the
  agent's credential at any address, or both sides keyless on one
  address. Other overlaps start with a warning by design.

## Out of scope for this repository

- Malware or DLP scanning of tool payloads. It is intentionally absent here.
- FIPS validation. Algorithms are Ed25519 and SHA-256 from `cryptography`.

Ledger entries and the head are AES-256-GCM ciphertext. The data key is
wrapped by a ledger key stored outside the ledger directory. The head needs
both the principal signature and a witness signature. The witness key is also
outside the ledger directory. Stealing only the principal key does not decrypt
the log, does not sign a new head, and does not mint a capability token.
The minting key is `<ledger>.capability/capability.pem`, also outside the
ledger directory. The gateway is given only the public half. Stealing the
ledger key decrypts. Stealing the witness key as well as the principal key
allows a forged head. Stealing the capability private key mints tokens.

A redemption intent is checkpointed before the tool runs. A later retry does
not run the tool. Concurrent calls are locked. A crash before the tool runs
blocks a retry; a tool exception does not.

Code scanning in CI is `.github/workflows/security.yml` (bandit). CodeQL is
`.github/workflows/codeql.yml`. It uploads results when code scanning is
enabled for this repository.
