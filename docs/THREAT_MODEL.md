# Threat model

This is the design model for `two-key-concept` 0.2.0, on the `working` branch (not tagged yet; `v0.1.12` is on `main`).
It is not a penetration test and it is not an independent review. The package is a
prototype. It is not a FIPS 140-3 validated module. Crypto is Ed25519,
SHA-256, and AES-256-GCM from the `cryptography` package.

How to report a vulnerability is [SECURITY.md](../SECURITY.md). The longer
narrative is the README. This file is the register. If the two disagree,
the code wins, then this file should be corrected.

## Assets

- The signed constitution and the two compilation hashes (bytecode and prose).
- The principal signing key. It signs the constitution and the ledger head.
  It does not sign capability tokens.
- The capability private key, outside the ledger directory
  (`<ledger>.capability/capability.pem`). `TwoKey` mints with it. The
  gateway receives only the public half.
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
  `tool_args`, except after a derive deny (`derive_failed:*`,
  `amount_mismatch`, `counterparty_mismatch`, `irreversible_mismatch`).
  `tool_args_on_derive_deny` defaults false. Set it true to send those
  bytes. Path B still runs either way. Other denies still attach the
  arguments. The proposal is withheld unless that judge sets
  `receives_proposal` or the quorum policy is `judge_inputs: record_and_proposal`.
  The default is record-only.
- Both paths run once the call is well-formed and within limits; a malformed or oversized
  call is denied before either path (size and digest only). `require_path_a_first` is stored on the policy and
  copied into `to_record`. `TwoKey.authorize` does not read it. There is no
  `short_circuit_path_b` setting on `TwoKey`.
- Gateway to the tool. The token is checked against the caller's argument
  bytes, then `redemption_started` is checkpointed, then the registered
  function is called with declared paths only. Unnamed keys are not passed
  in. A counterparty path is the canonical party, not the raw spelling.
  Nothing in this package scans those bytes.
- Process to the ledger. Appends and checkpoints take a POSIX `flock` on
  `<ledger>.lock` next to the ledger directory. If the file changed since
  this process loaded it, the write is refused. Redemption also takes a
  `flock` under `<ledger>.redeem-locks/`, outside the ledger directory.
  Where `fcntl` is absent, only the in-process lock remains.

## What this design is meant to stop

- A tool execution inside `authorize_from_agent`.
- An allow when either path denies or does not answer. A missing, malformed,
  or timed-out ballot is an abstention, not a yes. A ballot that names
  another judge abstains (`judge_id_mismatch`). The default needs one judge
  and has no diversity floors. `QuorumPolicy.high_assurance()` sets two
  vendors, one local judge, and a yes from a local judge;
  `QuorumPolicy.section4()` is that plus `require_path_a_first`. The flag is
  still not a skip. `min_distinct_providers` still defaults to 1.
- A judge that is the monitored agent: the same credential, a shared tenant
  id, the same model on the same endpoint or declared upstream, the same
  model through a loopback or private proxy or daemon with no declared
  `upstream:` (a keyless local proxy can forward to the agent's own
  account), or an identity that cannot be resolved refuses to start. The agent is declared by the operator, never
  by the agent. The same provider is allowed.
- A value read twice: every JSON and YAML input refuses a repeated key.
  Oversized or too-deeply nested arguments are a deny before the ledger.
- A token replay, a token used for different argument bytes, a token used
  after expiry (120 seconds unless you change it, at most 300), a token
  whose lifetime exceeds the TTL or whose issue time is in the future, and
  a token used after revocation or a constitution reload.
- A second run of a token after `redemption_started` has been checkpointed.
  A tool exception writes `redemption_aborted` and leaves the token usable.
- A silent edit of a ledger record that still verifies, and opening the log
  with only the principal key. The head needs the witness signature as well.

## Assumptions

- The gateway is the only holder of tool credentials. This package cannot
  stop an agent that can call the tool by another path.
- The principal key, the witness key, and the ledger key are not all in the
  attacker's hands.
- The action record describes the real call only for fields the tool spec
  names. Every loaded constitution has `tool_specs`. A tool with no spec
  does not redeem. A counterparty path requires `allow`. A party off that
  list does not authorize (`counterparty_not_allowed`), unless a blocked
  party is also present, in which case the block rule still denies.
  `deny_unmapped` defaults off. An unnamed key does not reach the tool.
  Setting the flag denies the call instead (`unmapped_field`).
- Judges are one key of two. The quorum does not prove the models are
  independent. The diversity floors are off by default; `high_assurance`
  turns them on. A judge that is not the same agent may still share a
  provider and its blind spots with the agent. A declared `upstream:` and a
  `model_prefix` resolution are operator-attested and not verified.
- Without a local judge, the constitution prose, the action record, and any
  attached tool arguments go to the cloud judges' vendors.

## Residual risks

These are accepted or still open. They are not bugs the design already
claims to close.

- No independent review, and no production deployment.
- Problem F is closed for loaded constitutions. `tool_specs` is required to
  sign and to load. `two_key/derive.py` reads amount and counterparties by
  JSON path. It does not read English. A present claim that disagrees with
  the bytes is a deny (`amount_mismatch`, `counterparty_mismatch`,
  `irreversible_mismatch`). An omitted amount or counterparty is filled from
  the bytes. A missing amount path, a non-numeric amount, or a currency path
  that is not `usd` denies. `data_class` is the stricter of the claim and
  `data_class_floor`. Two different middle classes (`personal`, `medical`,
  `financial`) join to `classified`. The token binds `spec_hash` and that
  form. The gateway recomputes the form from the same bytes and refuses a
  mismatch. Changing a spec changes `spec_hash`, so outstanding tokens fail
  at the gateway. This package does not classify free text and does not
  track per-value information flow. A counterparty the spec copies must be
  on that path's `allow` list. The tool receives the canonical value
  (`strip`, casefold), not the raw spelling. A party that is not listed is
  `counterparty_not_allowed`, unless a blocked party is also present, in
  which case the block rule denies. A currency path is delivered as `usd`.
  A path the spec does not declare does not
  change the form and is not passed to the tool. With `deny_unmapped` left
  off (the default), the call can still allow. With `deny_unmapped` set,
  the unnamed key is `unmapped_field`. Neither mode interprets the value.
  `payload` names a value that may be present. With no `shape`, the path
  covers that value and its children, and the value is not classified.
  `shape` of `string`, `number`, or `list` (strings only) refuses a
  different kind. `max_length` bounds a string or a list. A boolean is not
  a number. `payload_shape` is a derive deny. Shape does not read contents.
  Meaning stays with Path B, or with DLP in the full repository. The token still binds
  the caller's original argument bytes. Redeem with those same bytes. The
  function is called with the projection. Missing `data_class` still becomes
  `classified` before the floor, and the floor cannot lower that default.
  Missing `irreversible` is taken from the spec, so a tool signed as
  reversible stays reversible. A present `irreversible` claim that differs
  is `irreversible_mismatch`. The policy VM has one counterparty string. A
  list is reduced to one party, preferring any party on
  `deny_counterparties`, so a blocked party is not hidden behind an allowed
  one. A derived amount that is not finite or above the action sanity cap
  is `amount_unreadable`.
- A derive deny does not skip Path B. Judges still receive the normalized
  action record. They do not receive `tool_args` unless
  `tool_args_on_derive_deny` is true. A deny that is not a derive deny still
  attaches non-empty arguments. The tool still does not run on a deny.
- The gateway's verifier has no private key. The minting key is the
  capability key outside the ledger directory. The principal key still sits
  on the ledger object, because the head signature needs it. A token signed
  with that principal key fails `bad_signature`. A process that keeps the
  `TwoKey` object can still mint. A process that is given only the gateway
  cannot.
- Stealing the ledger key decrypts the log. Stealing the principal key does
  not, and it does not mint a token the gateway will accept. Stealing the
  capability private key does. Stealing the witness key as well as the
  principal key can forge a head. There is no external anchor, so those
  keys plus the ledger key are enough to rewrite a ledger that never leaves
  the machine.
- A crash after `redemption_started` and before the tool runs refuses a
  retry, even if the tool did not run. Exactly-once execution is not claimed.
- Where `fcntl` is absent, another process can still append. This package
  does not claim cross-process exclusion on those platforms.
- There is no TEE. Username/password and OAuth device-code judge auth are
  rejected. Use `env`, `keyring`, or `callback`.

## Out of scope

- The prototype status itself and missing FIPS validation.
- Prompt injection that Path A denies because the structured record tripped
  a rule.
- A vulnerability in a judge vendor's API.
- Using this package as an MCP server, as user login, or as a DLP or
  antivirus product. It is none of those.
- Full per-value information-flow tracking, and a content classifier. A
  tool-spec floor is not a taint label. Scanning, PKI, anchoring, seed
  phrases, and hybrid ML-DSA are in
  [two-key](https://github.com/Insomniac-VibeLabs/two-key), not here. See
  [SCOPE.md](SCOPE.md).

## What to re-check when the code changes

- `two_key/core.py`: both paths run once the call is well-formed and within limits, and `authorize_from_agent` does not call a tool. A spec disagreement denies after both paths answer.
- `two_key/derive.py`: JSON paths only. A claim can raise a data class and cannot lower one. Disagreement denies. `deny_unmapped` defaults off and drops unnamed keys at the tool. A counterparty path requires `allow`. Payload `shape` checks kind only. A declared path with no shape covers its children.
- `two_key/quorum.py`: an abstention is not a yes, ballots pair with judges by position, the default has no diversity floors (high_assurance has them), vendor names compare case-insensitively, and `require_path_a_first` is not a skip. `tool_args_on_derive_deny` defaults false. Path B still runs.
- `two_key/gateway.py`: argument hash of the caller's bytes, spec hash, recomputed form, then `redemption_started`, then the tool with declared paths only. The verifier has no private key. No scanner.
- `two_key/capability.py`: the token fields are tool, args hash, ledger root, ledger size, the two constitution hashes, `spec_hash`, and, when issued, `form` and `claimed_data_class`. The signing key is the capability key, not the principal key. TTL default is 120 seconds, at most 300.
- `two_key/identity.py`, `netloc.py`: judge versus monitored agent from operator configuration only; HMAC credential fingerprints; local means the loopback, RFC 1918, or fc00::/7 allowlist.
- `two_key/strict.py`: every JSON and YAML input refuses duplicate keys.
- `two_key/ledger.py`: the ledger key, the witness key, the capability key, the append lock, and the redemption locks stay outside the directory. The ledger does not load the capability private key. The principal key is not a decryption key and not the minting key. A stale in-memory ledger refuses to append.
