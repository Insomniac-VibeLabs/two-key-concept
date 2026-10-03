# Changes

## 0.1.0 — 2026-10-02

Initial concept repository, private, Apache-2.0.

Taken from `Insomniac-VibeLabs/two-key` branch `10.2.2026` (`b9e588e`) as the
reference, then cut down to the initial two-key:

- signed constitution, Path A policy VM, Path B judge quorum
- hash-chained ledger with a signed head and Merkle root bound into the token
- single-use gateway redemption
- judge transport kept: no SDK, no streaming, connection reuse, no redirects,
  one HTTP 400 fallback that drops schema / cache / reasoning knobs
- monitored-agent hooks kept: agents are untrusted regardless of host;
  `authorize_from_agent` always runs both paths and does not execute tools

Not included: scanning, antivirus, DLP, PKI, anchoring, seed phrases, ledger
encryption, hybrid ML-DSA.

Engineering note, not a conception entry. The dated conception record stays
in the `two-key` repository.
