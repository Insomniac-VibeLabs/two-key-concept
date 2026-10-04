# Scope

`two-key-concept` is the first working cut. Package version 0.2.0 (branch `working`, not tagged yet). Tag `v0.1.12`
is on `main`. `v0.1.6` stays on the previous tree.

It keeps:

- a signed constitution, Path A bytecode, and a policy VM that does not read English
- required `tool_specs` that fill Path A's form from argument bytes. Omitting them does not load. `deny_unmapped` defaults off: an unnamed key does not reach the tool. Set the flag to deny it. A counterparty path requires `allow`. A payload `shape`, when set, locks the value to a string, a number, or a list of strings and does not read it
- Path B judge hooks for xAI, OpenAI-compatible APIs, Anthropic, Gemini, and local Ollama. One judge by default, no diversity floors; `high_assurance` turns them on. No judge may be the monitored agent. After a derive deny, argument bytes are withheld from judges unless `tool_args_on_derive_deny` is set. Path B still runs
- monitored-agent hooks; `authorize_from_agent` does not execute a tool
- an AES-256-GCM ledger, a ledger key, and a witness key outside the ledger directory
- a capability key outside the ledger directory. The gateway verifies with the public half only
- a single-use token and a gateway that alone is meant to run the tool

It does not keep scanning, antivirus, DLP, PKI, permissioned-chain
anchoring, seed phrases, or hybrid ML-DSA. Those are in
[two-key](https://github.com/Insomniac-VibeLabs/two-key).

Read [FIT.md](FIT.md) before adopting it, [COMPARISON.md](COMPARISON.md)
before treating it as a substitute, and [THREAT_MODEL.md](THREAT_MODEL.md)
before treating a residual risk as closed.
