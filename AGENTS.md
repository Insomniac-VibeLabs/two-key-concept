# AGENTS.md

Guidance for coding agents working in this clone of
[Insomniac-VibeLabs/two-key-concept](https://github.com/Insomniac-VibeLabs/two-key-concept).

This file is a short contributor guide for agents. Product and API context for
any LLM reader is in [llms.txt](llms.txt). Do not replace one with the other.

## Scope

Concept line only: signed constitution, Path A bytecode, Path B judge hooks,
monitored-agent hooks, encrypted ledger, single-use capability token, and a
verify-only gateway. Prototype. Apache-2.0.

Do **not** add scanning, antivirus, DLP, PKI, chain anchoring, seed phrases, or
hybrid ML-DSA here. Those belong in `Insomniac-VibeLabs/two-key`. See
[docs/SCOPE.md](docs/SCOPE.md).

## Branch and commit rules

- Package 0.2.1 is tag `v0.2.1` on `main` and `working`. Do not move `v0.2.0`
  (`2f756ac`). `v0.1.12` and `v0.1.6` stay on their trees.
- Do not push, force-push, or open PRs unless the operator asks.
- Never commit keys, ledgers, or credentials.
- Update `CHANGES.md` when behavior or configuration changes. Read
  `CHANGES.md` "Upgrading from 0.1.12" before changing 0.2.0 config shapes.

## Install and version matrix

Requires Python ≥ 3.10. Package name `two-key-concept`, import name `two_key`,
version `0.2.1`, tag `v0.2.1`. Not on PyPI.

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[yaml]"
python -m unittest discover -s tests
python -m two_key demo
```

| Extra | Provides | When needed |
| --- | --- | --- |
| (none) | `cryptography>=41` | Ed25519, SHA-256, AES-256-GCM ledger |
| `yaml` | PyYAML | `.yaml` rules and judge configs |

Git install:  
`pip install "two-key-concept @ git+https://github.com/Insomniac-VibeLabs/two-key-concept.git@v0.2.1"`

## PYTHONPATH gotcha

Both this package and full `two-key` import as `two_key`. Do not put both
repository roots on `PYTHONPATH`. Use a dedicated virtualenv and
`pip install -e` for the tree you are editing. Imports from the wrong tree
are silent and wrong.

## Tests and docs

- Tests: `python -m unittest discover -s tests` (no network). Keep the suite
  network-free; use `two_key.testing` doubles only where the docs allow.
- When a claim changes, update `README.md`, `docs/HOWTO.md`, `docs/FIT.md`,
  `docs/COMPARISON.md`, `docs/THREAT_MODEL.md`, `docs/SCOPE.md`, `CHANGES.md`,
  and `llms.txt` as needed.
- Keep [docs/HOWTO.md](docs/HOWTO.md) "Known trade-offs by configuration"
  accurate when a config trade-off changes.

## Crypto and security changes

Crypto here is Ed25519 and SHA-256 via `cryptography`, plus AES-256-GCM for
ledger ciphertext. The ledger key, witness key, and capability private key
live outside the ledger directory. The gateway must verify only; it must not
mint.

Before changing authorization, tokens, the gateway, the ledger, or judge ≠
agent identity checks: consult the team's Cybersecurity Practitioner. Report
vulnerabilities per [SECURITY.md](SECURITY.md); do not open a public issue for
an unfixed security bug.

## Fail-closed defaults to preserve

- A missing ballot is not a yes.
- Both paths run once the call is well-formed and within limits.
- `authorize_from_agent` does not execute a tool.
- `require_path_a_first` is not a skip.
- JSON/YAML inputs refuse duplicate keys. Oversized or malformed calls deny
  before either path.
- Default quorum needs one judge and has no diversity floors;
  `QuorumPolicy.high_assurance` / `profile: high_assurance` adds two vendors,
  one local judge, and a local yes.
- `tool_specs` is required. A disagreeing claim is a deny.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the human contributor checklist.
