# Threat model

This is the design model for `two-key-concept` 0.2.1 (tag `v0.2.1` on `main`). `v0.2.0` stays on `2f756ac`. The model is unchanged from 0.2.0.
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
  and has no diversity floors. `QuorumPolicy.high_assurance()` needs judges
  from two model makers (the operator's `maker:` labels, not verified), one
  local judge, and a yes from a local judge;
  `QuorumPolicy.section4()` is that plus `require_path_a_first`. The flag is
  still not a skip. `min_distinct_providers` still defaults to 1.
- A judge that is the monitored agent: the same credential, a shared tenant
  id, the same model on the same endpoint or upstream (different declared
  tenants do not lift this unless the logged opt-in
  `allow_same_model_distinct_tenant` is set and both sides have different
  declared tenants and different keys), the same
  model through a loopback or private proxy or daemon with no declared
  `upstream:` (a keyless local proxy can forward to the agent's own
  account), or an identity that cannot be resolved refuses to start. The agent is declared by the operator, never
  by the agent. The same provider is allowed.
- A value read twice: every JSON and YAML input refuses a repeated key.
  Oversized or too-deeply nested arguments are a deny before the ledger.
  Inputs stop at 62 levels, two under the encoder's 64, so the ledger and
  judge wrappers always encode.
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
- Trusting the agent's claimed fields instead of reading them from the
  argument bytes is closed for loaded constitutions. `tool_specs` is required to
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
  Meaning stays with Path B. A DLP hook is planned (see
  [ROADMAP.md](../ROADMAP.md)). The token still binds
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
- What the ledger holds today: the agent's proposal text in full (the
  `proposal` entry), the derived form (`action_normalized.form`: the amount,
  counterparty, and counterparties read from the argument bytes), reasons,
  digests, and sizes. It never holds the raw argument bytes of an oversized
  or dropped value, only its size, digest, or key name. It never holds keys.
  Anyone who can decrypt the log can read the proposal text and the derived
  amount and counterparties.
- A crash after `redemption_started` and before the tool runs refuses a
  retry, even if the tool did not run. Exactly-once execution is not claimed.
- Where `fcntl` is absent, another process can still append. This package
  does not claim cross-process exclusion on those platforms.
- There is no TEE. Username/password and OAuth device-code judge auth are
  rejected. Use `env`, `keyring`, or `callback`.
- The signatures are not quantum resistant. Ed25519 signs the constitution,
  the ledger head (principal and witness), and capability tokens. A
  sufficiently capable quantum computer could forge an Ed25519 signature.
  The exposure is greatest for long-lived signatures, the constitution and
  the ledger head. A capability token lives at most 300 seconds, so it is a
  smaller exposure. AES-256-GCM and SHA-256 are not the concern at these
  sizes. Hybrid signatures are planned (see [ROADMAP.md](../ROADMAP.md)).

## Out of scope

- The prototype status itself and missing FIPS validation. A planned
  approved mode (see [ROADMAP.md](../ROADMAP.md)) would run on a validated
  module. It would not validate this package.
- Prompt injection that Path A denies because the structured record tripped
  a rule.
- A vulnerability in a judge vendor's API.
- Using this package as an MCP server, as user login, or as a DLP or
  antivirus product. It is none of those. An optional MCP adapter and
  scanner hooks are planned (see [ROADMAP.md](../ROADMAP.md)). They would sit
  in front of or beside the gateway, and they would not make this package a
  server or a scanner.
- Full per-value information-flow tracking, and a content classifier. A
  tool-spec floor is not a taint label. Scanning engines, anchoring, and
  seed phrases are not here and are not planned. Planned scanner hooks, key
  backup, PKI with certificate recovery, and hybrid signatures are in
  [ROADMAP.md](../ROADMAP.md). See [SCOPE.md](SCOPE.md).

## Planned changes to this model

These come from [ROADMAP.md](../ROADMAP.md). None is in 0.2.1, and nothing in
this section describes current behavior. Each item is added to the sections
above in the release that ships it.

- Key backup (target 0.3). New asset: the backup bundle. It holds the same
  secrets as the keys above, so it is treated as equal to them. The ledger
  key and the witness key are meant to be backed up separately from each
  other, because the residual risks above say that those keys plus the
  principal key can rewrite a ledger. A weak passphrase becomes a new
  residual risk.
- Ledger export for SIEM (target 0.4). New boundary: ledger to exporter to
  SIEM. Export decrypts, so the exported stream leaves encryption at rest. It
  is meant to carry digests, sizes, and reason codes, not argument values.
  It is meant to use a field allowlist that leaves out the proposal text and
  the derived amount and counterparty, which the ledger holds today.
  Whoever can read the SIEM becomes a new audience for ledger metadata.
- Inspection hooks for DLP and antivirus (target 0.5). New trust boundary:
  the scanner. A scanner error, timeout, or missing result is meant to be a
  deny. A scanner sees only what the tool spec lets through, so a payload
  value it cannot read stays a residual risk. Where the hook runs relative to
  the judges is an open choice, because cloud judges receive `tool_args`
  today.
- MCP adapter (target 0.6). New boundary: MCP client to proxy to MCP server.
  The assumption that the gateway is the only holder of tool credentials
  becomes the central one, because an agent that can reach an MCP server
  directly bypasses the proxy. A `tool_specs` draft made from MCP schemas is
  a proposal for the principal to review and sign, not trusted input.
- PKI and certificate recovery (target 0.7). New assets: the certificate
  authority key (a personal local CA or an enterprise CA), issued
  certificates, the revocation list, and recovery material (a backup bundle,
  a recovery key, or key shares). New boundary: certificate validation, meaning
  chain building to a configured trust anchor, validity period, key usage, and
  revocation. A stolen CA key lets an attacker mint identities the package
  accepts, so it is treated as equal to the principal key or higher. Recovery
  is itself an attack path: a stolen recovery key, enough colluding or
  coerced custodians, or a social-engineered recovery request can replace an
  identity. Recovery is meant to be a ledger event and to end with the old
  certificate revoked. Validity checks depend on a correct clock. Existing
  bare-key setups stay valid.
- Post-quantum signatures (target 0.8). New assets: a second signing key per
  signing role, and larger signatures in the constitution, ledger head, and
  possibly tokens. A hybrid signature is meant to verify only when both
  halves verify. New risk to design against: a downgrade, where the
  post-quantum half is stripped. Every signed format carries an algorithm
  identifier, and a verifier that expects the hybrid form refuses a
  classical-only one. Existing 0.2.x ledgers stay readable.
- FIPS approved mode (target 0.9). New boundary: the cryptographic provider.
  The mode is meant to refuse to start unless the library runs on a FIPS
  140-3 validated module in approved mode, and to refuse algorithms outside
  the approved set. The module's certificate and version are meant to be
  recorded in `constitution_loaded`. The claim is limited to "runs on a
  validated module". This package stays unvalidated, and the mode does not
  cover the rest of the host. How a hybrid signature is treated in approved
  mode depends on what the validated module supports, and is decided when
  the mode is built.
- Local GUI (target 0.10). New boundary: browser to a local server. It is
  meant to bind to loopback only and to require a per-session token, which
  is meant to address other local pages, cross-site requests, and DNS
  rebinding. It is the first place decrypted ledger content is displayed, so
  anyone who can see the screen or reach the local port is a new audience. It
  is meant to show digests, sizes, and reason codes, not argument values.
  Filtering by judge needs per-judge ballot records, which the ledger does
  not hold today. They are meant to carry the judge id, the vote, and a
  capped error only, never the rationale text, which is model output and may
  quote arguments.
  Configuration edits change policy, so the GUI is meant never to hold the
  principal key. It prepares a constitution and hands it to the existing
  signing command. A GUI that is reachable from another machine is out of
  scope.
- Generic spec field types (planned, not scheduled). A typed field per
  argument path, each kind with its own limits. `amount` and `counterparty`
  are meant to become ordinary typed fields. Until then the model above
  describes the two special kinds used today.

## What to re-check when the code changes

- `two_key/core.py`: both paths run once the call is well-formed and within limits, and `authorize_from_agent` does not call a tool. A spec disagreement denies after both paths answer.
- `two_key/derive.py`: JSON paths only. A claim can raise a data class and cannot lower one. Disagreement denies. `deny_unmapped` defaults off and drops unnamed keys at the tool. A counterparty path requires `allow`. Payload `shape` checks kind only. A declared path with no shape covers its children.
- `two_key/quorum.py`: an abstention is not a yes, ballots pair with judges by position, the default has no diversity floors (high_assurance has them), maker names compare case-insensitively, and `require_path_a_first` is not a skip. `tool_args_on_derive_deny` defaults false. Path B still runs.
- `two_key/gateway.py`: argument hash of the caller's bytes, spec hash, recomputed form, then `redemption_started`, then the tool with declared paths only. The verifier has no private key. No scanner.
- `two_key/capability.py`: the token fields are tool, args hash, ledger root, ledger size, the two constitution hashes, `spec_hash`, and, when issued, `form` and `claimed_data_class`. The signing key is the capability key, not the principal key. TTL default is 120 seconds, at most 300.
- `two_key/identity.py`, `netloc.py`: judge versus monitored agent from operator configuration only; HMAC credential fingerprints; local means the loopback, RFC 1918, or fc00::/7 allowlist.
- `two_key/strict.py`: every JSON and YAML input refuses duplicate keys.
- `two_key/ledger.py`: the ledger key, the witness key, the capability key, the append lock, and the redemption locks stay outside the directory. The ledger does not load the capability private key. The principal key is not a decryption key and not the minting key. A stale in-memory ledger refuses to append.
