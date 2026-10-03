# How to run the concept

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

The signature covers the prose and the hard rules. A modified file will not
load. Missing `data_class` defaults to `classified`, and missing
`irreversible` defaults to true, so an incomplete action record fails closed
against the example rules.

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

Local Ollama is `http://localhost:11434` only. Plain HTTP to any other host
is refused.

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
  --agent-session principal-session-1
```

Exit status is 0 on allow and 2 on deny. The ledger directory holds
ciphertext only. `witness.pem` is created on first open. Move it off this
host after the first checkpoint if the principal key and the ledger files
live on the same machine.

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
gw = ToolGateway(tk.ledger, tk.issuer, tk.compiled, tools={
    "email_draft": lambda args: {"drafted": args["to"]},
})
result = gw.invoke(decision.token, "email_draft", {"to": "ada@example"})
```

The gateway checks the signature, expiry, tool, argument hash, constitution
hashes, ledger prefix root, and that nothing revoked or reloaded the
constitution after issuance. The token is single-use. A tool exception does
not consume it, so the same token can be retried. There is no content
scanner on the way in or out.

Username/password and OAuth device-code auth are rejected. Use `env`,
`keyring`, or `callback`.

## Stop

```python
tk.revoke("principal stop")
```

Outstanding tokens then fail at the gateway.
