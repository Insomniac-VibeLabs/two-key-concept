# Scope

`two-key-concept` is the first working cut. Package version 0.1.9 on branch
`working`. Not a release tag. `v0.1.6` remains the tagged release on `main`.

It keeps:

- a signed constitution, Path A bytecode, and a policy VM that does not read English
- required `tool_specs` that fill Path A's form from argument bytes. Omitting them does not load. `deny_unmapped` defaults off. An unnamed key is unread payload unless that tool sets the flag
- Path B judge hooks for xAI, OpenAI-compatible APIs, Anthropic, Gemini, and local Ollama. Diversity floors default on and can be turned off
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
