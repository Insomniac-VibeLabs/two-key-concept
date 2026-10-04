# Changes

## 0.1.0 — 2026-10-02

Initial concept repository, private, Apache-2.0.

Taken from `Insomniac-VibeLabs/two-key` branch `10.2.2026` (`b9e588e`) as the
reference, then cut down to the initial two-key:

- signed constitution, Path A policy VM, Path B judge quorum
- hash-chained ledger with a signed head and Merkle root bound into the token
- single-use gateway redemption
- judge transport kept: no SDK, no streaming, connection reuse, no redirects,
  one HTTP 400 fallback that drops schema / cache / reasoning knobs
- monitored-agent hooks kept: agents are untrusted regardless of host;
  `authorize_from_agent` always runs both paths and does not execute tools

Not included: scanning, antivirus, DLP, PKI, anchoring, seed phrases, ledger
encryption, hybrid ML-DSA.

Engineering note, not a conception entry. The dated conception record stays
in the `two-key` repository.

## 0.1.1 — 2026-10-02

On branch `10.2.2026`. `prev` and `main` stay at 0.1.0.

- Gateway runs the tool before redemption. A tool exception leaves the token redeemable.
- Merkle root is RFC 6962. Odd counts no longer duplicate the last leaf.
- Username/password and OAuth device-code auth are rejected.
- Ledger entries and head are AES-256-GCM. Head is signed by the principal and a witness key.
- `two-key authorize` runs both paths and does not execute the tool.
- CodeQL workflow added so code scanning could run while the repository was private.

## 0.1.2 — 2026-10-02

Private concept package. Not published to PyPI. Tag `v0.1.2`.

- Ledger key and witness key are created outside the ledger directory. The principal key neither decrypts the log nor signs a head alone.
- `authorize` no longer accepts `--allow-test-doubles`.
- Tests cover a second-process reload and a missing witness key.
- Bandit workflow added. CodeQL remains for when Advanced Security is enabled.
- Crash-after-success redemption window stays documented and unchanged.

## Docs — 2026-10-02

Clarified the GitHub file list. The middle column is the last commit message,
not a description of each file. README no longer calls the package private.
Added `llms.txt` and repository topics for discovery. No behavior change.

## 0.1.3 — 2026-10-02

- Redemption writes and checkpoints an intent before the tool runs. A retry of that intent does not run the tool.
- A tool exception appends an abort and leaves the token usable.
- A crash after the intent and before the tool runs also blocks a retry.

## 0.1.4 — 2026-10-03

Tag `v0.1.4`. No behavior change. The `v0.1.3` tag stays on the earlier tree.

- README architecture diagram: a monitored agent only proposes, Path B judges vote with their own credentials, and the token is returned to the caller. Path B still runs when Path A denies.

## Docs — 2026-10-03

On branch `10.3.2026.2`, cut from `main`. `main` was not updated.

- Added `docs/FIT.md`, `docs/COMPARISON.md`, `docs/THREAT_MODEL.md`, and `docs/SCOPE.md` for this package, not for the full `two-key` repository.
- `README.md`, `docs/HOWTO.md`, `llms.txt`, `SECURITY.md`, and `CONTRIBUTING.md` point at them.
- `SECURITY.md` no longer calls this repository private.
- No behavior change. Package version stays 0.1.4.

## Fixes — 2026-10-03

On branch `10.3.2026.2`. `main` was not updated.

- Path B comments match the code. Both paths always run. `require_path_a_first` is recorded and not consulted. The unused `judge_proposal` value in `convene` is gone; per-judge filtering is unchanged.
- Comments no longer point at `DESIGN_OPTIONS.md`, `PRIOR_ART.md`, or `CONCEPTION_NOTES.md` as files in this repository. `docs/HOWTO.md` has the Qwen2.5 section the example config links to.
- `two-key authorize` defaults `--data-class` to `classified` and `--irreversible` to true, matching `normalize_action`. `--no-irreversible` turns that flag off.
- A mismatched principal key on the ledger head reports a principal-key mismatch, not a ledger-key mismatch.
- Appends and checkpoints take `<ledger>.lock` outside the ledger directory and refuse if another writer changed the file. Redemption locks moved to `<ledger>.redeem-locks/`, also outside. `fcntl` is optional, so the package still imports where that module is absent.
- Workflows set an explicit `permissions` block. The CodeQL job still has `security-events: write`.
- The 0.1.1 changelog no longer calls the repository private in the present tense.

## 0.1.6 — 2026-10-03

Tag `v0.1.6`. `v0.1.2`, `v0.1.3`, and `v0.1.4` stay on their earlier commits.

`two-key` main is 0.1.5. This package skipped 0.1.5 so this release is higher.
The two packages do not share a version line.

Pulled in by merge of pull request #4, previously unreleased:

- Fit, comparison, threat-model, and scope pages.
- `two-key authorize` defaults match `normalize_action`: classified, and irreversible true.
- A stale ledger refuses to append. Ledger and redemption locks stay outside the ledger directory.
- Path B comments match the code. Both paths still run.

No behavior change in this version bump itself. Not published to PyPI.

## 0.1.7 — 2026-10-03

On branch `working`, cut from `main` at `e29b776` (`v0.1.6`). `main` was not
updated. This version is not a release tag. `v0.1.6` stays on the previous tree.

- A signed constitution may include `tool_specs`. Every allow-listed tool then
  needs a spec. Amount and counterparties are read from the argument bytes by
  JSON path. A present claim that disagrees is a deny. An omitted amount or
  counterparty is filled from the bytes. An omitted `irreversible` follows
  the spec. `data_class` can only get stricter than `data_class_floor`, and
  a missing class still starts at `classified`. The token binds `spec_hash`
  and the derived form. The gateway recomputes that form. A spec change
  invalidates outstanding tokens.
- `tool_specs: null` is refused. Omitting the key is the only legacy path.
- A derived amount that is not finite, or above the action sanity cap, is a deny.
- A constitution that omits `tool_specs` is unchanged: the agent's form is
  still trusted. The offline demo uses that path.
- No English scanner and no per-value information-flow tracking. Quorum
  defaults and the minting key are unchanged. Both paths still run.
- Not published to PyPI.

## 0.1.8 — 2026-10-03

On branch `working`. Not a release tag. `main` was not updated. `v0.1.6` stays
the tagged release.

- `tool_specs` is required. A constitution that omits the key does not sign
  and does not load. There is no remaining path that trusts the agent's form.
- Diversity floors default on: two vendors, one local judge, and a yes from
  a local judge. `QuorumPolicy.without_diversity_floors()` opts out.
  `require_path_a_first` still defaults off and is still not a skip.
  `TwoKey` refuses to start when the judge set misses the floor.
- Tokens are signed by a capability key outside the ledger directory
  (`<ledger>.capability/capability.pem`). The gateway keeps only the public
  half. The principal key still signs the constitution and the ledger head.
  A token signed with the principal key does not redeem.
- Not published to PyPI.

## 0.1.9 — 2026-10-03

On branch `working`. Not a release tag. `main` was not updated. `v0.1.6` stays
the tagged release.

- `deny_unmapped` is optional and defaults off. An argument key the spec does
  not name stays unread payload and does not change the form. A tool that
  sets the flag denies that key (`unmapped_field`). `payload` names a value
  that may be present and is not interpreted. A declared path covers that
  value and its children. The spec does not list every nested key.
- A value copied from a declared path is unchanged. Free text is still not
  classified. Both paths still run, including after a derive deny, so judges
  still see `tool_args`.
- Not published to PyPI.

## 0.1.10 — 2026-10-03

On branch `working`. Not a release tag. `main` was not updated. `v0.1.6` stays
the tagged release.

- After a derive deny, judges do not receive `tool_args` unless
  `QuorumPolicy.tool_args_on_derive_deny` is set. Path B still runs. Other
  denies still attach non-empty arguments. An allow still attaches them.
- An unnamed argument key does not reach the tool. `deny_unmapped` still
  defaults off: the call can allow, and the gateway drops the key. Setting
  the flag denies (`unmapped_field`). The token still binds the caller's
  original argument bytes.
- A counterparty path requires `allow`. A party that is not listed is
  `counterparty_not_allowed`, unless a blocked party is also present, in
  which case the block rule still denies. The tool receives the canonical
  party, not the raw spelling.
- A `payload` path is still not classified. Both paths still run.
- Not published to PyPI.

## 0.1.11 — 2026-10-03

On branch `working`. Not a release tag. `main` was not updated. `v0.1.6` stays
the tagged release.

- A payload path may set `shape` to `string`, `number`, or `list` (a list of
  strings). `max_length` bounds a string or a list. A different kind is
  `payload_shape`, which is a derive deny. Shape does not read the contents.
  Omit `shape` and the value, including its children, is still copied unread.
- No payload class floor. What the text means stays with Path B, or with DLP
  in the full `two-key` repository.
- Not published to PyPI.

## 0.1.12 — 2026-10-03

Tag `v0.1.12` on `main`. No behavior change in this version. The `working`
line through 0.1.11 is this tree. `v0.1.6` stays on the previous tree.
Not published to PyPI.

## 0.2.0 — 2026-10-03

On branch `working`. Not tagged yet; `main` stays at `v0.1.12`. Not
published to PyPI. This version changes configuration and refuses some
setups 0.1.12 accepted: read "Upgrading from 0.1.12" below first.

### Changed

- Path B needs one judge by default and has no diversity floors.
  `QuorumPolicy.high_assurance()` (`profile: high_assurance`) turns on two
  vendors, one local judge, and a local yes; use it for destructive,
  irreversible, financial, or external-send tools. `required_yes` defaults
  to `min(2, number of judges)`.
- No judge may be the monitored agent. The operator declares the agent
  (`monitored_agent:` or `TwoKey(monitored_agent=...)`). Refused at start:
  the same credential fingerprint, a shared tenant id, the same normalized
  model on the same endpoint `host:port` (local aliases such as `0.0.0.0`,
  `127.1`, `localhost.localdomain`, and this machine's own addresses are one
  endpoint), the same model through a loopback or private proxy or daemon
  with no declared `upstream:`, the same model reaching the same upstream
  (declared upstreams and `ollama.com` for a cloud model count as endpoints;
  allowed for different declared accounts), or an unresolved identity (an
  unknown router, or a local proxy serving an alias model without a declared
  `upstream:`). Declared tenants are scoped by provider family, not by a
  proxy's address, and upstreams are normalized (`host[:port]`, default port
  removed). The same provider is allowed; `allow_same_provider_judge`
  is a no-op. The result, with `resolved_by` for each identity, is in
  `constitution_loaded`; each decision carries `identities_digest` and
  `policy_digest` (the full quorum policy is in `constitution_loaded` only).
  `two_key.audit.check_decision_digests(ledger)` recomputes both and lists
  any decision that does not match.
- Credential fingerprints are HMAC-SHA256 of the stripped secret under a
  per-install key, `<ledger>.ledger-key/fingerprint.key` (O_EXCL, 0600).
- Locality comes from the endpoint host and an explicit allowlist
  (loopback, RFC 1918, fc00::/7), never from a declared flag or
  `is_private`. A `:cloud` / `-cloud` model (an Ollama cloud model) is cloud
  and never local for every judge class (OllamaJudge, OpenAI-compatible,
  and the rest), and a monitored agent with one is hosted `cloud`.
- Start-up refuses: no judge, `timeout_seconds: null`, duplicate or empty
  judge ids, `require_local_yes` with no local judge, an unreadable judge
  credential, unknown top-level config keys, overlapping payload and field
  paths (compared case-insensitively), a TTL outside 1-300 seconds, and the in-process test agent unless
  every judge is a test double.
- Every JSON and YAML input refuses a repeated key and JSON NaN/Infinity.
- Ballots pair with judges by position; a ballot naming another judge
  abstains (`judge_id_mismatch`). Vendor and provider names compare
  case-insensitively (NFKC, trimmed) in the diversity and distinct-provider
  counts.
- The raw action claim is capped at 64 KiB before it is read
  (`action_too_large`, size and digest only). A tool name is an identifier
  of at most 128 characters. `malformed_action:` reasons name the field,
  never a value or an unknown key name.
- Denies instead of errors: arguments or a proposal over 256 KiB
  (`args_too_large`, `proposal_too_large`; only size and digest are
  ledgered), arguments nested too deeply (`invalid_call:tool args are nested too deeply`,
  checked before the size so Python 3.10 and 3.11 give the same reason), an
  unreadable amount (`derive_failed:amount_unreadable`, for example
  `10**400`) or other derived value (`derive_failed:value_unreadable:<Type>`),
  any other exception in `authorize` (`internal_error:<Type>`), and a deny
  that cannot be ledgered (`ledger_failed:<LedgerError message>`, or
  `ledger_failed:<Type>` for any other exception; also on stderr).
- Tokens: a lifetime over the TTL (`ttl_too_long`), an issue time more than
  5 s ahead (`issued_in_future`), and missing or non-finite time fields
  (`malformed_token`) are refused. The capability key is created
  exclusively, never regenerated after issuance, and its fingerprint is
  pinned and checked by the gateway. A ledger that has issued tokens but
  has no pinned fingerprint is refused at start-up
  (`capability_key_unpinned:`).
- CLI: the bearer token is never printed (`token_jti`, `token_digest`);
  `--emit-token PATH` writes it 0600 and refuses to overwrite;
  `--agent-session-env NAME` replaces `--agent-session`; a `--key` readable
  by group or others is refused; `--ttl-seconds` is 1-300; decisions record
  `origin: cli`.
- The judge prompt describes any tool call with derived fields.
- The gateway ledgers every refusal of an authenticated token as
  `gateway_denied` (`reason`, `jti`, `tool` if it is a short identifier,
  else `tool_size`/`tool_digest`, and `tool_args_size`/`tool_args_digest`).
  A token that does not verify writes nothing.
- Arguments are encoded once per `authorize` and once per gateway call:
  the canonical bytes give the size check and the token's `args_hash`
  (they were serialized up to three times). The size cap measures compact
  JSON (no spaces after `,` and `:`).
- `two-key demo` opens its ledger in a subdirectory of its temporary
  directory, so the ledger key, witness, capability key, and lock files no
  longer outlive the run in the system temp directory. The tests do the
  same.
- `authorize_from_agent` measures the proposal text before parsing it:
  over 1,048,576 characters is `proposal_too_large`, and text that is not
  a string (including `None`) or does not parse is `malformed_proposal`.
  Both are ledgered denies with size and digest only, instead of an
  exception.
- The ledger key is created with O_EXCL and O_NOFOLLOW at mode 0600 in a
  0700 directory, and is refused on open if it is group- or
  world-readable, a symlink, or not 32 bytes (`ledger_key_insecure:`,
  `ledger_key_unreadable:`). The wrapped data key (`keywrap.json`) is
  written to an O_EXCL temporary file under the ledger lock and moved into
  place with `os.replace`.

### Upgrading from 0.1.12

1. Add a `monitored_agent:` block to judges.yaml (or pass
   `TwoKey(monitored_agent=...)`): `model`, `provider`, `base_url`, and
   `credential_env` (or `credential: none` for a keyless local agent). Set
   that environment variable where Two-Key starts.
2. Make every judge key readable at start-up, and keep it different from
   the agent's key.
3. Set `timeout_seconds` to a number. Give every judge a unique `id`.
4. If you relied on the old default floors, add `profile: high_assurance`
   to the quorum block. If you want one yes from two judges, set
   `required_yes: 1`.
5. Write `tenant` as a mapping (`tenant: {organization: org-123}`), and add
   `upstream:` to any judge or agent behind a local proxy that serves an
   alias model, and to any local proxy or daemon that serves the same model
   as the other side (a daemon with its own weights declares its own
   address, for example `upstream: localhost:11434`).
6. Remove `allow_same_provider_judge`, unknown top-level keys, and any key
   repeated in one mapping.
7. CLI: replace `--agent-session VALUE` with `--agent-session-env NAME`,
   read the token from `--emit-token PATH`, and `chmod 600` the `--key`
   file. Keep `--ttl-seconds` at 300 or less.
8. A 0.1.12 ledger that has issued tokens has no pinned capability key and
   is refused (`capability_key_unpinned:`). Keep it for audit and start a
   new ledger directory.
9. Tests that use `testing.TEST_AGENT` must use only test-double judges;
   with a real judge, declare a real agent.
10. `Decision.to_record()` no longer includes `token`; it has `token_jti`
    and `token_digest`. Read the bearer token from `decision.token`.
11. `QuorumPolicy().required_yes` is `None` until `TwoKey` resolves it
    against the judge list (`min(2, judges)`). Code that read the default
    as an integer must handle `None` or set `required_yes` explicitly.
12. A judge on a LAN or private address with `local_weights: true` is now
    cloud for the session check (only loopback is not), so `authorize`
    needs an `agent_session` (`cloud_judge_session_required`). It still
    counts as a local judge for the quorum floors.
13. Tokens minted by 0.1.12 will most likely be refused
    (`capability_key_mismatch`): 0.1.12 did not pin the capability key in
    `constitution_loaded`. Tokens live at most 300 seconds; re-authorize.

#### Troubleshooting: start-up refusals

| Message starts with | Cause | Fix |
|---|---|---|
| `monitored_agent_required:` | No agent declared | Add `monitored_agent:` (step 1) |
| `monitored_agent ...: declare <field>` / `unknown key(s)` / `declare exactly one of credential_env or credential: none` | Incomplete or misspelled declaration | Give `model`, `provider`, `base_url`, and one credential key; allowed keys are `id`, `model`, `provider`, `base_url`, `credential_env`, `credential`, `tenant`, `upstream` |
| `monitored_agent ...: credential_env X is not set` | The agent key variable is unset | Export it where Two-Key starts |
| `monitored_agent ...: credential: none is only for a loopback or private-address agent` | `credential: none` on a remote host | Use `credential_env` |
| `judge_matches_agent: ... same credential fingerprint` | A judge uses the agent's key (whitespace ignored) | Give the judge its own key |
| `judge_matches_agent: ... same model '<m>' on the same endpoint <host:port>` | The judge is the agent's model at the agent's endpoint | Use another model, or the same model through another endpoint and key |
| `judge_matches_agent: ... same tenant <id>` | Same Azure resource or deployment, Vertex project, Bedrock account and region, or declared org/project | Use a judge in another tenant |
| `judge_matches_agent: ... through a local proxy or daemon (...) with no declared upstream` | The same model as the agent through a loopback or private endpoint that declares no `upstream:` | Use another model, or declare `upstream:` on the proxy or daemon (a different provider, or its own address for local weights) |
| `judge_matches_agent: ... through the same upstream <host>` | The same model reaching the agent's endpoint or declared upstream (or `ollama.com` for a cloud model) | Use another model or provider; for a different account declare `tenant:` on both sides |
| `judge_matches_agent: ... upstream unresolved` | Unknown router or host, or a local proxy serving an alias | Use a `maker/model` id, or declare `upstream:` (attested, not verified) |
| `... tenant must be a mapping` / `unknown tenant key(s)` | Old string or list `tenant` | `tenant: {organization: ..., project: ..., account: ..., deployment: ...}` |
| `... upstream entries must be non-empty strings` | Empty or non-string `upstream` | A host string or a list of them |
| `in_process_agent_refused:` | `TEST_AGENT` (or `in-process://`) with a real judge, or without `allow_test_doubles` | Declare the real agent |
| `judge '<id>': credential could not be read at start-up` | Judge key variable, keyring, or callback unavailable | Make it readable at start-up |
| `no_judges:` | Empty judge list | Configure at least one judge |
| `Path B needs a hard deadline` / `timeout_seconds must be a positive number` | `timeout_seconds: null` | Set a number of seconds |
| `duplicate_judge_id:` | Two judges share an id, or an id is empty | Make ids unique |
| `judge set is not heterogeneous enough: require_local_yes_without_local_judge` | `require_local_yes` with no local judge | Add a loopback/private judge with local weights, or drop the flag |
| `judge set is not heterogeneous enough: insufficient_vendors` / `insufficient_local_judges` | `high_assurance` floors not met (vendors now compare case-insensitively) | Add a vendor or a local judge, or leave the default profile |
| `unknown top-level key(s)` | A typo such as `quorm`, or a key other than `judges`, `quorum`, `monitored_agent` (agents.yaml: `agents`) | Fix the key |
| `duplicate key '<k>'` | A key repeated in one JSON/YAML mapping (config, rules, constitution, `--args`) | Keep one |
| `non-standard JSON constant` | `NaN` or `Infinity` in JSON | Use a finite number |
| `payload path ... overlaps the field path` | A payload path equals, contains, or sits under an amount, currency, or counterparty path, ignoring case (`TO.name` vs `to.name`) | Split the paths |
| `ttl_out_of_range:` | `ttl_seconds` not an integer from 1 to 300 | Use 1-300 |
| `capability_key_missing:` / `capability_key_changed:` | The token key was removed or replaced after tokens were issued | Restore `<ledger>.capability/capability.pem`, or start a new ledger |
| `capability_key_unpinned:` | The ledger has issued tokens but its last `constitution_loaded` entry pins no token key (a 0.1.12 ledger, or an edited one) | Keep the old ledger for audit and start a new one |
| `capability_key_is_principal_key` | The token key equals the principal key | Remove the copied key; Two-Key creates its own |
| `fingerprint_key_insecure:` / `fingerprint_key_unreadable:` / `fingerprint_key_unavailable:` | `<ledger>.ledger-key/fingerprint.key` is group/world-readable, a symlink, the wrong size, or cannot be created | `chmod 600` it, restore it, or make the directory writable |
| `ledger_key_insecure:` / `ledger_key_unreadable:` / `ledger_key_unavailable:` | `<ledger>.ledger-key/ledger.key` is group/world-readable, a symlink, the wrong size, or cannot be created | `chmod 600` it, restore it, or make the directory writable |
| `key_file_insecure:` / `key_file_unreadable:` | `--key` readable by group or others, a symlink, or missing | `chmod 600` the key |
| `--agent-session took the secret on the command line` | Old CLI flag | `--agent-session-env NAME` |
| `refusing to overwrite` | `init-key` or `--emit-token` target exists | Pick a new path |
| `environment variable NAME is not set` | `--agent-session-env` names an unset variable | Export it |

`allow_same_provider_judge is deprecated and has no effect` is a warning
on stderr, not a refusal.

#### Troubleshooting: denies

| Deny or abstain reason | Cause | Fix |
|---|---|---|
| `action_too_large` | The action claim is over 64 KiB of UTF-8 JSON | Send a normal claim; only size and digest are ledgered |
| `malformed_action:tool: longer than 128 characters` / `tool: not an identifier ...` | The tool name is too long or has characters outside `a-z 0-9 _ . : / -` | Rename the tool |
| `malformed_action:unknown action fields (<n>)` / `<field>: ...` | An unknown or invalid action field (the reason names the field, not the value) | Fix the claim |
| `args_too_large` / `proposal_too_large` | Over 256 KiB of UTF-8 JSON, or agent proposal text over 1,048,576 characters | Send less; only size and digest are ledgered |
| `malformed_proposal` | `authorize_from_agent` got text that is not a string, not JSON, or has a missing, extra, or repeated key | Fix the agent's reply; the reason names no key |
| `invalid_call:<why>` (authorize and gateway) | Arguments nested too deeply, NaN, or a non-string key | Flatten or fix the arguments |
| `derive_failed:amount_unreadable` | The amount cannot be read (for example `10**400`, `"1e400"`, or a non-number) | Send a readable amount |
| `derive_failed:value_unreadable:<Type>` | Another derived value cannot be read (for example nested too deeply to walk) | Send a readable value |
| `internal_error:<Type>` | Any other exception inside `authorize` | Read the ledger entry; report it |
| `ledger_failed:<message>` / `ledger_failed:<Type>` | The deny could not be written: a `LedgerError` gives its message (for example `ledger file changed by another writer; reopen the ledger`), any other exception its type (also printed on stderr) | Check the ledger directory |
| `cloud_judge_session_required` | A judge not on loopback, and no `agent_session` | Pass the agent session (`--agent-session-env`) |
| `cloud_judge_reused_agent_session` | A judge key equals the agent session | Give the judge its own key |
| `judge_id_mismatch` (abstain) | A ballot named another judge | Check the judge; the ballot does not count |
| ballot `duplicate key` / `non-standard JSON constant` (abstain) | The judge repeated a key or sent NaN | Not a yes; check the model |
| `duplicate_judge_id` | Judges with the same id reached `convene` | Make ids unique |
| `judge_set_not_heterogeneous:...` | A floor is not met at decision time | As for the start-up message |
| `insufficient_yes:<y><<k>` with two judges | `required_yes` now defaults to 2 when there are two or more judges | Set `required_yes: 1` if one yes is enough |
| `ttl_too_long` / `issued_in_future` / `malformed_token` | A token outlives the TTL, is dated ahead, or has missing or non-finite times | Re-authorize; check clocks |
| `capability_key_mismatch` | The token key is not the one pinned in the ledger | Re-authorize with the current key |
| `gateway_denied` (ledger entry) | The gateway refused an authenticated token; `reason` says why (`args_mismatch`, `tool_mismatch`, `already_redeemed`, ...) | Read `reason`; values are never ledgered, only size and digest |
| `AgentConfigError: agent proposal has a duplicate key` | `parse_proposal` or `MonitoredAgent.complete` got a proposal with a repeated key (`authorize_from_agent` denies `malformed_proposal` instead) | Fix the agent's JSON |

### Planned (not done)

- Spec field types become generic. Today a tool spec knows two special
  field kinds, `amount` (USD or cents) and `counterparties`, plus unread
  `payload` paths. The plan is a typed field per argument path, each kind
  with its own limits: string, int, decimal, enum, identifier/principal,
  path, URL, email, and opaque bytes. `amount` and `counterparty` stop
  being special cases and become ordinary typed fields that rules can
  name. Until then the action record keeps `amount_usd` and `counterparty`
  as fields, with neutral defaults for tools that have neither.
