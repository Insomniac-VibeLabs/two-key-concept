# Scope

`two-key-concept` is the first working cut. Package version 0.2.1 (tag `v0.2.1` on `main`). Tag `v0.2.0` stays on `2f756ac`. Tag `v0.1.12`
is on `main`. `v0.1.6` stays on the previous tree.

It keeps:

- a signed constitution, Path A bytecode, and a policy VM that does not read English
- required `tool_specs` that fill Path A's form from argument bytes. Omitting them does not load. `deny_unmapped` defaults off: an unnamed key does not reach the tool. Set the flag to deny it. A counterparty path requires `allow`. A payload `shape`, when set, locks the value to a string, a number, or a list of strings and does not read it
- Path B judge hooks for xAI, OpenAI-compatible APIs, Anthropic, Gemini, and local Ollama. One judge by default, no diversity floors; `high_assurance` turns them on. No judge may be the monitored agent. After a derive deny, argument bytes are withheld from judges unless `tool_args_on_derive_deny` is set. Path B still runs
- monitored-agent hooks; `authorize_from_agent` does not execute a tool
- an AES-256-GCM ledger, a ledger key, and a witness key outside the ledger directory
- a capability key outside the ledger directory. The gateway verifies with the public half only
- a single-use token and a gateway that alone is meant to run the tool

Modules that carry these rules include `two_key/identity.py` (judge ≠ agent),
`two_key/strict.py` (duplicate-key JSON/YAML), `two_key/audit.py` (decision
digest checks), and the per-install fingerprint key beside the ledger
(`*.ledger-key/fingerprint.key`).

It does not keep scanning, antivirus, DLP, PKI, permissioned-chain
anchoring, seed phrases, or hybrid ML-DSA. Those are in
[two-key](https://github.com/Insomniac-VibeLabs/two-key).

## Planned additions

[ROADMAP.md](../ROADMAP.md) lists optional additions to this repository. None
exists in 0.2.1, and the lists above describe 0.2.1. When one ships, this file
and [THREAT_MODEL.md](THREAT_MODEL.md) change in the same release.

- Key backup and recovery (target 0.3): encrypted backup and restore of this
  package's own keys (principal, capability, ledger, witness). This is not
  PKI, X.509 identities, or seed-phrase backup. Those stay in `two-key`.
- Ledger export for SIEM (target 0.4): a command that verifies and decrypts
  the ledger locally and writes events without argument values.
- Inspection hooks for DLP and antivirus (target 0.5): an interface that
  calls external scanners. This package still does not scan or classify
  content itself.
- MCP adapter (target 0.6): an optional proxy in front of the gateway. This
  package is still not an MCP server.
- Post-quantum signatures (target 0.7): hybrid Ed25519 plus ML-DSA-65 for the
  long-lived signatures (the constitution and the ledger head), sized to this
  repository's scope. The hybrid ML-DSA work today is in `two-key`.
- FIPS approved mode (target 0.8): an opt-in mode that refuses to start unless
  the cryptography library runs on a FIPS 140-3 validated module in approved
  mode, and that refuses algorithms outside the approved set. This package is
  not FIPS validated today, and that mode would not make it validated.
  Running on a validated module is not the same as this package being
  validated or compliant, and the docs will not describe it that way.
- Local GUI (target 0.9): a loopback-only interface for configuration and
  ledger auditing, built on the CLI and the existing file formats. It does not
  hold the principal key, and it is not a hosted or multi-user service.

Read [FIT.md](FIT.md) before adopting it, [COMPARISON.md](COMPARISON.md)
before treating it as a substitute, and [THREAT_MODEL.md](THREAT_MODEL.md)
before treating a residual risk as closed.
