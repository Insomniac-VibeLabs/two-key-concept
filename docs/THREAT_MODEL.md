# Threat model

This is the design model for `two-key-concept` 0.1.4. It is not a
penetration test and it is not an independent review. The package is a
prototype. It is not a FIPS 140-3 validated module. Crypto is Ed25519,
SHA-256, and AES-256-GCM from the `cryptography` package.

How to report a vulnerability is [SECURITY.md](../SECURITY.md). The longer
narrative is the README. This file is the register. If the two disagree,
the code wins, then this file should be corrected.

## Assets

- The signed constitution and the two compilation hashes (bytecode and prose).
- The principal signing key.
- The ledger key and the witness key, both outside the ledger directory
  (`<ledger>.ledger-key` and `<ledger>.witness`).
- The wrapped data key stored inside the ledger directory.
- Judge credentials and monitored-agent credentials. They are not the same secret.
- The capability token and the argument bytes it is bound to.
- Tool credentials, which only the gateway should hold.
- The ledger head and the hash chain.

## Actors

- The principal, who holds the signing key and writes the constitution.
- An untrusted agent, local or cloud. Hosting is not trust.
- Path B judges, each with its own credential. A judge can be wrong.
- The caller that invokes authorize, then the gateway.
- Anyone who can read or write the ledger directory, the ledger key, or the
  witness key.

## Trust boundaries

- Agent to `authorize_from_agent`. The reply is a proposal. The method does
  not execute a tool. A cloud judge must not reuse an agent credential.
  A missing session is a deny (`cloud_judge_session_required`).
- Caller to Path A. The VM sees the normalized action record, not the proposal.
- Caller to Path B. Judges see the constitution prose and the normalized
  record. Non-empty tool arguments are attached on that record as
  `tool_args`. The proposal is withheld unless that judge sets
  `receives_proposal` or the quorum policy is `judge_inputs: record_and_proposal`.
  The default is record-only.
- Both paths always run. `require_path_a_first` is stored on the policy and
  copied into `to_record`. `TwoKey.authorize` does not read it. There is no
  `short_circuit_path_b` setting on `TwoKey`.
- Gateway to the tool. The token is checked, then `redemption_started` is
  checkpointed, then the registered function is called with the same
  argument mapping. Nothing in this package scans those bytes.
- Process to the ledger. Appends in one process share a lock. Redemption
  also takes a POSIX `flock` on `.redeem-<jti>.lock` inside the ledger
  directory. `fcntl` is imported at load, so this package does not import
  where that module is absent.

## What this design is meant to stop

- A tool execution inside `authorize_from_agent`.
- An allow when either path denies or does not answer. A missing, malformed,
  or timed-out ballot is an abstention, not a yes. The section-4 floors
  (two vendors, one local judge) are off unless `QuorumPolicy.section4()` is
  used. That profile sets `require_path_a_first`. The flag is still not a skip.
- A token replay, a token used for different argument bytes, a token used
  after expiry (120 seconds unless you change it), and a token used after
  revocation or a constitution reload.
- A second run of a token after `redemption_started` has been checkpointed.
  A tool exception writes `redemption_aborted` and leaves the token usable.
- A silent edit of a ledger record that still verifies, and opening the log
  with only the principal key. The head needs the witness signature as well.

## Assumptions

- The gateway is the only holder of tool credentials. This package cannot
  stop an agent that can call the tool by another path.
- The principal key, the witness key, and the ledger key are not all in the
  attacker's hands.
- The action record describes the real call. This package does not derive
  `amount_usd`, `data_class`, `counterparty`, or `irreversible` from the
  argument bytes. That is problem F, below.
- Judges are one key of two. The quorum does not prove the models are
  independent. The diversity floors are off by default.

## Residual risks

These are accepted or still open. They are not bugs the design already
claims to close.

- No independent review, and no production deployment.
- Problem F is open. Path A is only as good as the structured fields it is
  given. A lie in `amount_usd`, `data_class`, `counterparty`, or
  `irreversible` can pass Path A while the argument bytes say something
  else. The gateway binds those bytes. It does not check that they match
  the structured fields. The token is not bound to amount, data class, or
  counterparty. Missing `data_class` becomes `classified` and missing
  `irreversible` becomes true, but only when the field is absent.
  `two-key authorize` always passes the fields: `--data-class` defaults to
  `public`, and `--irreversible` defaults to false.
- `two_key/quorum.py` still says Path B runs only after Path A allows.
  `two_key/core.py` always runs both paths.
- `two_key/ledger.py` reports "head principal key does not match the ledger
  key" when the principal public key mismatches. That check is not the
  encryption key.
- Comments in `two_key/action.py`, `two_key/quorum.py`, and
  `examples/judges.yaml` point at `DESIGN_OPTIONS.md`, `PRIOR_ART.md`,
  `CONCEPTION_NOTES.md`, and a Qwen how-to anchor. None of those exist in
  this repository.
- The issuer object holds the principal private key. `verify` uses the
  public key, but this package does not give the gateway a verify-only
  issuer. A process that can redeem can also mint if it has that object.
- Stealing the ledger key decrypts the log. Stealing the principal key does
  not. Stealing the witness key as well as the principal key can forge a
  head. There is no external anchor, so those two keys plus the ledger key
  are enough to rewrite a ledger that never leaves the machine.
- A crash after `redemption_started` and before the tool runs refuses a
  retry, even if the tool did not run. Exactly-once execution is not claimed.
- Ledger appends are not locked across processes. The cross-process lock is
  only the per-token redemption flock. Redemption lock files sit inside the
  ledger directory.
- There is no TEE. Username/password and OAuth device-code judge auth are
  rejected. Use `env`, `keyring`, or `callback`.

## Out of scope

- The prototype status itself and missing FIPS validation.
- Prompt injection that Path A denies because the structured record tripped
  a rule.
- A vulnerability in a judge vendor's API.
- Using this package as an MCP server, as user login, or as a DLP or
  antivirus product. It is none of those.
- Scanning, PKI, anchoring, seed phrases, and hybrid ML-DSA. Those are in
  [two-key](https://github.com/Insomniac-VibeLabs/two-key), not here. See
  [SCOPE.md](SCOPE.md).

## What to re-check when the code changes

- `two_key/core.py`: both paths run, and `authorize_from_agent` does not call a tool.
- `two_key/quorum.py`: an abstention is not a yes, and `require_path_a_first` is not a skip.
- `two_key/gateway.py`: argument check, then `redemption_started`, then the tool. No scanner.
- `two_key/capability.py`: the token fields are tool, args hash, ledger root, ledger size, and the two constitution hashes. TTL default is 120 seconds.
- `two_key/ledger.py`: the ledger key and the witness key stay outside the directory, and the principal key is not a decryption key.
