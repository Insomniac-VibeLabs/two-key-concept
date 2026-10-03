# How to run the concept

Whether this package is the right control is [FIT.md](FIT.md). What it is
not a substitute for is [COMPARISON.md](COMPARISON.md). Boundaries and
residual risk are [THREAT_MODEL.md](THREAT_MODEL.md). What this package
leaves out is [SCOPE.md](SCOPE.md).

Commands are from the repository root.

## Install

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[yaml]"
python -m unittest discover -s tests
```

## Create a principal key and sign a constitution

```bash
python -m two_key init-key ./keys
python -m two_key sign-constitution \
  --key ./keys/principal.pem \
  --prose examples/constitution.md \
  --rules examples/hard_rules.yaml \
  --out constitution.signed.json
```

The signature covers the prose, the hard rules, and `tool_specs`. A modified
file will not load. `tool_specs` is required. A bare rule list, a missing
key, `null`, and an empty mapping are refused. `examples/hard_rules.yaml`
has a spec for every allow-listed tool. Amount, counterparty, and
irreversible are read from the argument bytes, and a claim that disagrees
is a deny. `data_class` is the stricter of the claim and the tool's
`data_class_floor`. This package does not classify free text, so a public
tool can mention "classified ads". A tool that carries medical text needs
`data_class_floor: medical` (or `classified`). A missing amount path, a
non-numeric amount, or a currency other than `usd` on `pay_bill` is a deny.
A spec with no amount path treats the amount as 0, so money in an unmapped
field is not seen.

Missing `data_class` still defaults to `classified` before the floor, and
a floor never lowers that. Missing `irreversible` follows the tool spec,
so a reversible tool stays reversible. A present claim that disagrees with
the spec is a deny. Pass `--data-class public` only when that class is
allowed after the floor, and pass `--no-irreversible` only for a tool the
spec marks reversible.

## Judges

`examples/judges.yaml` is the hook list: OpenAI-compatible (OpenAI and xAI),
Anthropic, Gemini, and Ollama. No vendor SDK is used. Each thread keeps one
connection per origin and does not follow redirects.

Cloud OpenAI and xAI send a strict ballot schema. xAI also sends
`reasoning_effort: low`. A single HTTP 400 drops those knobs and retries
once. The local ballot parser does not change on that retry. Any other
HTTP error abstains.

A cloud judge requires an `agent_session` string that is not the judge API
key. Reusing the judge credential as the session is a deny.

The diversity floors are on by default: at least two vendors, at least one
judge with `local_weights`, and a yes from a local judge. `examples/judges.yaml`
meets that with the cloud hooks plus local Qwen. To opt out, set
`min_vendors: 1`, `min_local_judges: 0`, and `require_local_yes: false` in
the quorum block, or call `QuorumPolicy.without_diversity_floors()`.
`require_path_a_first` stays off unless you set it. `TwoKey.authorize` does
not read it. Both paths still run. `min_distinct_providers` still defaults
to 1, so that count is not itself a floor.

Local Ollama is `http://localhost:11434` only. Plain HTTP to any other host
is refused. An Ollama judge counts as local weights unless you set
`local_weights: false`.

### Recommended local judge: Qwen2.5-7B-Instruct

`examples/judges.yaml` sets the local judge to `qwen2.5:7b`
(Qwen2.5-7B-Instruct, Apache-2.0, Copyright 2024 Alibaba Cloud). The weights
are not in this repository. Pull them with Ollama, then leave the example
`base_url` as it is:

```bash
ollama pull qwen2.5:7b
```

The model card is <https://huggingface.co/Qwen/Qwen2.5-7B-Instruct>.

## Authorize from the command line

This runs both paths and prints the decision. It does not execute the tool.

```bash
python -m two_key authorize \
  --key ./keys/principal.pem \
  --ledger ./ledger \
  --constitution constitution.signed.json \
  --judges examples/judges.yaml \
  --tool email_draft \
  --args '{"to":"ada@example"}' \
  --proposal "draft a status note" \
  --data-class public \
  --no-irreversible \
  --agent-session principal-session-1
```

`--data-class` defaults to `classified`, and `--irreversible` defaults to
true. Those are the same fail-closed defaults as a missing field in
`normalize_action`. The command above sets public and reversible so the
example rules allow a draft. `--no-irreversible` is the off switch.

Exit status is 0 on allow and 2 on deny. The ledger records and the head
are ciphertext. The append lock is `<ledger>.lock` next to the ledger
directory. Redemption locks are `<ledger>.redeem-locks/` there too, not
inside the ledger directory. First open writes `<ledger>.ledger-key/ledger.key` and
`<ledger>.witness/witness.pem` next to the ledger directory, not inside it.
The authorize command does not accept test-double judges.

## Authorize from Python


```python
from pathlib import Path
from two_key.constitution import load_envelope, verify_signed
from two_key.core import TwoKey
from two_key.judges.config import load_config_file
from two_key.keys import load_private_key
from two_key.ledger import Ledger

key = load_private_key("keys/principal.pem")
judges, policy = load_config_file(Path("examples/judges.yaml"))
ledger = Ledger("ledger", key)
tk = TwoKey.load(ledger, key.public_key(), load_envelope("constitution.signed.json"),
                 judges, private_key=key, quorum=policy)
decision = tk.authorize(
    {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
    {"to": "ada@example"},
    "draft a status note",
    agent_session="principal-session-1",
)
```

`decision.token` is set only when both paths allow and the signed ledger
head was written. The gateway is the only component that should call the tool.

## Monitored agents

`examples/agents.yaml` configures Grok, ChatGPT, Claude, Gemini, and a local
model. Hosting is recorded. It is not trust.

`authorize_from_agent` parses the proposal (`tool`, `arguments`, `proposal`,
and optional structured fields) and runs both paths. It does not call the
tool. Extra keys in the proposal are rejected.

Use a different API key for agents than for judges.

## Redeem

```python
from two_key.gateway import ToolGateway
gw = ToolGateway(tk.ledger, tk.issuer.verifier(), tk.compiled, tools={
    "email_draft": lambda args: {"drafted": args["to"]},
})
result = gw.invoke(decision.token, "email_draft", {"to": "ada@example"})
```

Passing `tk.issuer` also works. The constructor keeps a verifier, so
`gw.issuer.private_key` is `None` and `gw.issuer.issue(...)` raises
`verifier_cannot_mint`. The minting key is `<ledger>.capability/capability.pem`,
next to the ledger directory, not inside it. The public half is
`capability.pub.pem` beside it. The principal key on the ledger signs the
head. A token signed with that principal key does not redeem.

The gateway checks the signature, expiry, tool, argument hash, constitution
hashes, spec hash, the recomputed form, the ledger prefix root, and that
nothing revoked or reloaded the constitution after issuance. The token is
single-use. A tool exception does not consume it, so the same token can be
retried. There is no content scanner on the way in or out.

Username/password and OAuth device-code auth are rejected. Use `env`,
`keyring`, or `callback`.

A redemption intent is checkpointed before the tool runs. A crash after that
intent, including after the tool has returned, does not run the token again.
A tool exception appends an abort and leaves the token usable. A crash before
the tool runs also blocks a retry.

## Stop

```python
tk.revoke("principal stop")
```

Outstanding tokens then fail at the gateway.
