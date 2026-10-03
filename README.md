# Two-Key concept

Two independent keys must turn before an AI agent can act.

This repository is the initial concept, extracted from
[Insomniac-VibeLabs/two-key](https://github.com/Insomniac-VibeLabs/two-key)
after that line grew past the first working system. It keeps a working
ledger, Path A, Path B, and the judge and monitored-agent hooks. It does
not scan payloads and it has no antivirus or DLP hooks.

Apache License 2.0. See [LICENSE](LICENSE).

## What turns

1. Path A is a policy VM. Hard rules compile to bytecode. The VM reads only
   structured fields (`tool`, `amount_usd`, `data_class`, `counterparty`,
   `irreversible`). It does not read English. A fault is a deny.
2. Path B is a judge quorum. Judges are hooks for xAI/Grok, OpenAI,
   Anthropic, Gemini, and Ollama. A missing or malformed ballot does not
   count as yes.
3. A short-lived single-use token is issued only if both paths allow. The
   token is bound to the tool, the argument hash, and the ledger Merkle
   root at issuance.
4. The gateway redeems that token. It does not inspect file contents, mail,
   or tool output for DLP or malware.

Both paths always answer. A Path A deny does not skip Path B, so the ledger
has both results. `authorize_from_agent` runs both paths and does not
execute the tool. An agent is untrusted whether it is hosted locally or in
the cloud.

## What this repo leaves out

Left in the full `two-key` repository, on purpose:

- payload scanning, antivirus, and DLP hooks
- enterprise deployment modes and permissioned-chain anchoring
- X.509 / PKI identities and agent assertions
- seed-phrase backup and ledger encryption at rest
- hybrid ML-DSA-65

Crypto here is Ed25519 and SHA-256 via the `cryptography` package. Ledger
entries and the signed head are AES-256-GCM at rest. The head is signed by
the principal key and by a witness key created in the ledger directory
(`witness.pem`). Move that file off the ledger host; a stolen principal key
alone cannot then sign a new head. It is a prototype. It is not a FIPS
140-3 validated module.

## Run the offline demo

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[yaml]"
python -m unittest discover -s tests
python -m two_key demo
python -m two_key authorize --help
```

The demo uses fixed test-double judges. Real judges are configured in
`examples/judges.yaml`. See [docs/HOWTO.md](docs/HOWTO.md).

## Layout

| Path | What |
| --- | --- |
| `two_key/core.py` | `TwoKey.authorize` and `authorize_from_agent` |
| `two_key/policy_vm.py`, `compiler.py` | Path A |
| `two_key/quorum.py`, `two_key/judges/` | Path B and judge transport |
| `two_key/agents.py` | Monitored-agent hooks |
| `two_key/ledger.py` | Encrypted hash-chained ledger, principal and witness head |
| `two_key/capability.py`, `gateway.py` | Tokens and redemption, no scanning |
| `examples/` | Constitution, hard rules, judges, agents |
| `docs/HOWTO.md` | Operator how-to |
