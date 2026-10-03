# Is this for you

Prototype. Not a FIPS 140-3 validated module. Not on PyPI. There is no MCP
server in this release. Package `two-key-concept` version 0.1.6. Apache-2.0.
Crypto is Ed25519 and SHA-256.

This is the smaller package. It has a ledger, Path A, Path B, and judge and
monitored-agent hooks. It does not scan payloads. It has no PKI, no
anchoring, and no seed phrase. The larger package is
[two-key](https://github.com/Insomniac-VibeLabs/two-key).

## Use this if

- A tool should run only after Path A and Path B both allow. Path A is a
  policy VM over a structured action record. It does not read English. Path B
  is a judge quorum. Hooks exist for xAI, OpenAI-compatible APIs, Anthropic,
  Gemini, and local Ollama.
- The only component that runs the tool should be the gateway. It holds a
  single-use token, 120 seconds by default, signed by the principal key.
  The token is bound to the tool, the argument hash, the ledger Merkle root
  and size at issuance, and the constitution hashes (`bytecode_hash` and
  `nl_hash`). It is not bound to `amount_usd`, `data_class`, or
  `counterparty`.
- You want an encrypted ledger. Records and the head are AES-256-GCM. The
  ledger key and the witness key live outside the ledger directory. The
  principal key cannot unwrap the log and cannot sign a head alone.

## Do not use this if

- You need a content filter, or a moderation API, to be the authorization
  decision. Path A does not read the proposal.
- You need user login or MCP session authorization.
- You need a validated cryptographic module, or a control that has had an
  independent review. This release has not.
- You need DLP, antivirus, PKI, permissioned anchoring, a seed phrase, or
  hybrid ML-DSA. Those are in `two-key`, not here.

## Smallest working shape

From a checkout:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e ".[yaml]"
python -m two_key demo
```

The demo does not call a vendor. Real judges are `examples/judges.yaml`.
Operator steps are [HOWTO.md](HOWTO.md).

Read next: [COMPARISON.md](COMPARISON.md), [THREAT_MODEL.md](THREAT_MODEL.md),
[SCOPE.md](SCOPE.md).
