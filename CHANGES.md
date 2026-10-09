# Changes

## 0.1.0 — 2026-10-02

Initial concept repository, private, Apache-2.0.

Cut down to the initial two-key:

- signed constitution, Path A policy VM, Path B judge quorum
- hash-chained ledger with a signed head and Merkle root bound into the token
- single-use gateway redemption
- judge transport kept: no SDK, no streaming, connection reuse, no redirects,
  one HTTP 400 fallback that drops schema / cache / reasoning knobs
- monitored-agent hooks kept: agents are untrusted regardless of host;
  `authorize_from_agent` always runs both paths and does not execute tools

Not included: scanning, antivirus, DLP, PKI, anchoring, seed phrases, ledger
encryption, hybrid ML-DSA.

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

- Added `docs/FIT.md`, `docs/COMPARISON.md`, `docs/THREAT_MODEL.md`, and `docs/SCOPE.md` for this package.
- `README.md`, `docs/HOWTO.md`, `llms.txt`, `SECURITY.md`, and `CONTRIBUTING.md` point at them.
- `SECURITY.md` no longer calls this repository private.
- No behavior change. Package version stays 0.1.4.

## Fixes — 2026-10-03

On branch `10.3.2026.2`. `main` was not updated.

- Path B comments match the code. Both paths always run. `require_path_a_first` is recorded and not consulted. The unused `judge_proposal` value in `convene` is gone; per-judge filtering is unchanged.
- Comments no longer point at design notes as if they were files in this repository. `docs/HOWTO.md` has the Qwen2.5 section the example config links to.
- `two-key authorize` defaults `--data-class` to `classified` and `--irreversible` to true, matching `normalize_action`. `--no-irreversible` turns that flag off.
- A mismatched principal key on the ledger head reports a principal-key mismatch, not a ledger-key mismatch.
- Appends and checkpoints take `<ledger>.lock` outside the ledger directory and refuse if another writer changed the file. Redemption locks moved to `<ledger>.redeem-locks/`, also outside. `fcntl` is optional, so the package still imports where that module is absent.
- Workflows set an explicit `permissions` block. The CodeQL job still has `security-events: write`.
- The 0.1.1 changelog no longer calls the repository private in the present tense.

## 0.1.6 — 2026-10-03

Tag `v0.1.6`. `v0.1.2`, `v0.1.3`, and `v0.1.4` stay on their earlier commits.

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
  outside this package.
- Not published to PyPI.

## 0.1.12 — 2026-10-03

Tag `v0.1.12` on `main`. No behavior change in this version. The `working`
line through 0.1.11 is this tree. `v0.1.6` stays on the previous tree.
Not published to PyPI.

## 0.2.0 — 2026-10-03

Tagged `v0.2.0` on `main` at `2f756ac` on 2026-10-07 (merge of PR #30).
Not published to PyPI. This version changes configuration and refuses some
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
  (`same_model_same_upstream`: declared upstreams and `ollama.com` for a
  cloud model count as endpoints, and different declared tenants do not
  lift it), or an unresolved identity (an
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
  ledgered), arguments nested more than 62 levels (`invalid_call:tool args are nested too deeply`,
  checked before the size so every Python version gives the same reason), an
  unreadable amount (`derive_failed:amount_unreadable`, for example
  `10**400`) or other derived value (`derive_failed:value_unreadable:<type_tag>`),
  any other exception in `authorize` (`internal_error:<Type>`), and a deny
  that cannot be ledgered (`ledger_failed:<LedgerError message>`, or
  `ledger_failed:<Type>` for any other exception; also on stderr).
- Logged opt-in `quorum: allow_same_model_distinct_tenant: true` (default
  off). It allows the agent's model on the same endpoint or upstream only
  when both sides declare a tenant, the scoped tenant ids are non-empty and
  disjoint, and both have keys with different fingerprints. It prints a
  stderr warning and records `same_model_tenant_optin` and
  `same_model_tenant_optin_pairs` (both tenant labels) in
  `constitution_loaded`. It is part of `policy_digest`. A misspelled key is
  refused.
- HOWTO has a "Known trade-offs by configuration" section.
- A host that is not a recognized vendor, router, or inference host is
  treated as a proxy for the same-model check, like a local one. A `maker/`
  model prefix no longer identifies it. With the agent's model and no
  non-overlapping `upstream:`, it is refused ("through a local or
  unrecognized proxy or daemon ... no declared upstream",
  `same_model_unknown_upstream`).
- One copy: tool args, the action claim, and the proposal are each copied
  once into built-in types (`canonical.to_plain`), in `authorize` and at the
  gateway. Any `collections.abc.Mapping` becomes a dict, a tuple becomes a
  list, and a `str`, `int` or `float` subclass becomes its base value. The
  size cap, the token's `args_hash`, the judges, the ledger and the tool all
  read that copy. A custom Mapping is no longer measured by its `str()`.
  Before this, a 5 MB Mapping in `raw` could get a token. The sizer no longer
  falls back to `str()` or `repr()`: a value it cannot encode as JSON counts
  as too large. Copying stops after `cap // 2` values, so a Mapping that
  never stops iterating is `args_too_large` / `action_too_large`
  (`*_size: -1`) rather than a hang.
- Depth: the canonical encoder refuses containers nested more than 64
  levels (`canonical.MAX_DEPTH`), counted without recursion. Tool args, the
  action claim, and a structured (non-text) proposal are held to 62
  (`MAX_INPUT_DEPTH`). That leaves room for the two levels an input gains
  inside a ledger entry or a judge's record (`raw.tool_args`), so an accepted
  input always encodes again. One level more is a ledgered deny:
  `invalid_call:tool args are nested too deeply`,
  `malformed_action:action claim is nested too deeply`, or
  `malformed_proposal`. It is never `internal_error`. A ledger body that
  still cannot be encoded is recorded by `Ledger.append_bounded` with only
  its short scalar fields, `body_size`, `body_digest`, `body_omitted`, and
  `body_error`. The entry is not lost.
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
- B1: `agent_id` and `hosting` on `authorize` / `authorize_from_agent` are
  operator/library metadata. Non-`str` is `invalid_agent_metadata`; after
  strip, over 256 characters is `agent_metadata_too_large` (ledger
  `field`/`size`/`digest` only). `append_bounded` with `body_omitted` on a
  path about to issue a token becomes `ledger_body_too_large` instead of an
  allow. Shared helper: `two_key.agent_meta`.
- Decision `origin` (library/CLI label) uses the same 256-char / str caps as
  B1 metadata (`normalize_origin`). Oversize or non-str is a fail-closed deny
  with `field`/`size`/`digest` or `got: non_str` only — never the full value,
  and no token. Ledger type labels use `type_tag` (allowlisted or ≤32 chars),
  never raw unbounded `__name__`.
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

These are the 0.2.0 messages. 0.2.2 changed the judge rows: several refusals below only warn now, and the message text changed. For 0.2.2, see "Upgrading from 0.2.1" and the HOWTO section on the monitored agent.

| Message starts with | Cause | Fix |
|---|---|---|
| `monitored_agent_required:` | No agent declared | Add `monitored_agent:` (step 1) |
| `monitored_agent ...: declare <field>` / `unknown key(s)` / `declare exactly one of credential_env or credential: none` | Incomplete or misspelled declaration | Give `model`, `provider`, `base_url`, and one credential key; allowed keys are `id`, `model`, `provider`, `base_url`, `credential_env`, `credential`, `tenant`, `upstream` |
| `monitored_agent ...: credential_env X is not set` | The agent key variable is unset | Export it where Two-Key starts |
| `monitored_agent ...: credential: none is only for a loopback or private-address agent` | `credential: none` on a remote host | Use `credential_env` |
| `judge_matches_agent: ... same credential fingerprint` | A judge uses the agent's key (whitespace ignored) | Give the judge its own key |
| `judge_matches_agent: ... same model '<m>' on the same endpoint <host:port>` | The judge is the agent's model at the agent's endpoint | Use another model, or the same model through another endpoint and key |
| `judge_matches_agent: ... same tenant <id>` | Same Azure resource or deployment, Vertex project, Bedrock account and region, or declared org/project | Use a judge in another tenant |
| `judge_matches_agent: ... through a local or unrecognized proxy or daemon (...) with no declared upstream` | The same model as the agent through a loopback or private endpoint that declares no `upstream:` | Use another model, or declare `upstream:` on the proxy or daemon (a different provider, or its own address for local weights) |
| `judge_matches_agent: ... through the same upstream <host>` | The same model reaching the agent's endpoint or declared upstream (or `ollama.com` for a cloud model) | Use another model or a non-overlapping upstream (another provider); different tenants on one upstream are still refused |
| `judge_matches_agent: ... upstream unresolved` | Unknown router or host, or a local proxy serving an alias | Use a `maker/model` id, or declare `upstream:` (attested, not verified) |
| `... tenant must be a mapping` / `unknown tenant key(s)` | Old string or list `tenant` | `tenant: {organization: ..., project: ..., account: ..., deployment: ...}` |
| `... upstream entries must be non-empty strings` | Empty or non-string `upstream` | A host string or a list of them |
| `in_process_agent_refused:` | `TEST_AGENT` (or `in-process://`) with a real judge, or without `allow_test_doubles` | Declare the real agent |
| `judge '<id>': credential could not be read at start-up` | Judge key variable, keyring, or callback unavailable | Make it readable at start-up |
| `no_judges:` | Empty judge list | Configure at least one judge |
| `Path B needs a hard deadline` / `timeout_seconds must be a positive number` | `timeout_seconds: null` | Set a number of seconds |
| `duplicate_judge_id:` | Two judges share an id, or an id is empty | Make ids unique |
| `judge set is not heterogeneous enough: require_local_yes_without_local_judge` | `require_local_yes` with no local judge | Add a loopback/private judge with local weights, or drop the flag |
| `judge set is not heterogeneous enough: insufficient_makers` (`insufficient_vendors` through 0.2.1) / `insufficient_local_judges` | `high_assurance` floors not met (makers compare case-insensitively) | Add a judge whose model has another maker (`maker:`), or a local judge, or leave the default profile |
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
on stderr, not a refusal. So are `vendor is deprecated; use maker` and
`min_vendors is deprecated; use min_makers` (after 0.2.1).

#### Troubleshooting: denies

| Deny or abstain reason | Cause | Fix |
|---|---|---|
| `action_too_large` | The action claim is over 64 KiB of UTF-8 JSON | Send a normal claim; only size and digest are ledgered |
| `malformed_action:tool: longer than 128 characters` / `tool: not an identifier ...` | The tool name is too long or has characters outside `a-z 0-9 _ . : / -` | Rename the tool |
| `malformed_action:unknown action fields (<n>)` / `<field>: ...` | An unknown or invalid action field (the reason names the field, not the value) | Fix the claim |
| `args_too_large` / `proposal_too_large` | Over 256 KiB of UTF-8 JSON, or agent proposal text over 1,048,576 characters | Send less; only size and digest are ledgered |
| `malformed_proposal` | `authorize_from_agent` got text that is not a string, not JSON, nested too deeply to parse (a `RecursionError` on any Python version), or has a missing, extra, or repeated key | Fix the agent's reply; the reason names no key |
| `invalid_call:<why>` (authorize and gateway) | Arguments nested more than 62 levels, NaN, a non-string key, or an unsupported type (`unsupported_type`; never a raw type name) | Flatten or fix the arguments |
| `malformed_action:action claim is nested too deeply` | The action claim (usually `raw`) nests more than 62 levels | Flatten `raw` |
| `body_omitted: true` on a ledger entry | The entry's body could not be encoded; short scalars plus `body_size`/`body_digest`/`body_error` are kept, and `policy_digest`/`identities_digest` are always retained when present; temporary JSON for the digest writes non-JSON values as `<type_tag>` (never raw `__name__`) | Read `body_error`; report it |
| `derive_failed:amount_unreadable` | The amount cannot be read (for example `10**400`, `"1e400"`, or a non-number) | Send a readable amount |
| `derive_failed:value_unreadable:<type_tag>` | Another derived value cannot be read (for example nested too deeply to walk); type label is `type_tag` (≤32 chars), never raw `__name__` | Send a readable value |
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

- Generic spec field types moved to [ROADMAP.md](ROADMAP.md) (after 1.0, not scheduled).

## Cyber fail-closed pass — 2026-10-06 (in v0.2.0)

In tag `v0.2.0` (`2f756ac`), and so in `v0.2.1`. Issues addressed:

- **#9** — Declared upstream labels folded (NFKC / zero-width); bare `openai` maps to `api.openai.com`.
- **#8** — Empty `tenant: {}` refused (omit instead); same-model distinct-tenant opt-in documented as `constitution_loaded`-only.
- **#12** — Per-jti throttle: after the first `gateway_denied` for a jti, further denies still refuse but do not append repeats.
- **#11** — `append_bounded` `body_omitted` entries always retain `policy_digest` and `identities_digest`.
- **#16** — Bound `_denied_jtis`: mark jti only after successful `gateway_denied` append+checkpoint; LRU hard cap (`_MAX_DENIED_JTIS`, default 4096).
- **#17** — Complete (via #20 / #21): cap exception/reason ledger text (~300 chars + digest) via `cap_ledger_text` / `exception_ledger_error`. Covers quorum ballot error, both Path A `vm_fault` paths (`VMFault` and generic `Exception`), gateway `_record_deny` `ledger_failed`, core authorize/`_deny` `ledger_failed`, and gateway redemption `ledger_failed` sites. Non-`LedgerError` deny paths keep `type_tag` only.
- **#18** — `check_agent_meta_mapping` reports `got: non_mapping` for a non-Mapping `agent_meta` (field values stay `non_str`).
- **#19** — SHA-pin third-party GitHub Actions (`checkout`, `setup-python`, `codeql-action`) to full commit SHAs.
- **#20** — Cap dedicated `VMFault` `vm_fault:` reason via `exception_ledger_error` (parity with #17 generic Exception path).
- **#21** — Cap remaining `ledger_failed:{e}` / `ledger_failed:{le}` in `core.py` and `gateway.py` redemption paths via `cap_ledger_text`.
- **#22** — Clamp `max_denied_jtis` to `>= 1` (zero/negative no longer KeyError after deny).
- **#23** — Same-jti single-flight under `_denied_jtis_guard`: concurrent denies for one jti wait; at most one successful `gateway_denied` append per jti. Mark-after-success (#16) preserved.
- **#24** — `EncodingError` for a non-JSON type is the fixed label `unsupported_type` (never raw unbounded `__name__`). Authorize/gateway `invalid_call:` / `malformed_action:` suffixes and `*_error` ledger fields run through `cap_ledger_text`. `core._deny` stderr caps `reason` / `str(e)` before format (no full `{e}` then `[:500]`).
- **#25** — Same-jti `Condition.wait` is timed (default 30s, `deny_inflight_wait_seconds`); on timeout waiters still deny fail-closed without marking and without fail-open, so a stuck `append_bounded` cannot hang waiters forever.
- **#26** — `derive` `value_unreadable:` uses `type_tag(exc)` (never raw unbounded `__name__`); `derive_failed:` decision reasons are `cap_ledger_text`'d where stored. `append_bounded` / `omitted_body` JSON `default=` uses `type_tag(o)` so temporary size/digest allocation cannot balloon on a pathological class name.
- **#27** — LLM judge `transport:` / `malformed_response:` abstain errors use `type_tag(e)` (not raw `type(e).__name__`) into `ballot.error` (`QuorumResult.to_record`).
- **#28** — `deny_inflight_wait_seconds` requires finite positive (`math.isfinite`); `inf` / `nan` / ≤0 fall back to the 30s default (so `inf` cannot restore unbounded same-jti `Condition.wait`).
- README: removed the GitHub Pages `pages-build-deployment` Documentation Status badge (other badges kept).

## 0.2.1 — 2026-10-07

Tag `v0.2.1` on `main` and `working`. Docs and version only. No behavior
change. Not published to PyPI. `v0.2.0` stays on `2f756ac` and is not moved.

- Package version is 0.2.1 (`pyproject.toml`, `two_key.__version__`).
- README, AGENTS.md, and llms.txt name tag `v0.2.1` and install from
  `@v0.2.1`. The 0.2.0 README still said the package was untagged on
  `working`.

## 0.2.2 — 2026-10-09

Tag `v0.2.2` on `main` and `working`. Not published to PyPI. **This version
changes configuration and refuses some setups 0.2.1 accepted. Read
"Upgrading from 0.2.1" below first.** The step-by-step history is in the
commit messages of PRs #43 and #61.

### Changed

- **When a judge is the monitored agent (owner's decision, 2026-10-08).**
  A judge may run any model from any vendor. It is the agent, and `TwoKey`
  refuses to start (`judge_matches_agent:`), in two cases only:
  - it holds the agent's credential (an API token, or a username and
    password as one pair), at any address: a credential identifies its
    holder wherever it is sent (`same_credential`);
  - neither side has a credential and both are on one address
    (`host:port` as configured, every local alias folded to `localhost`,
    no DNS), so nothing tells them apart (`same_address_no_credential`).

  A side counts as keyless when it sends no credential, whatever is
  configured: a judge with `auth_header: none` (an Ollama judge's default)
  and an `ollama` agent without Basic auth. A configured agent credential
  that cannot be read at start-up refuses, for a local agent as well as a
  cloud one.

  What used to refuse and now only warns: the same model on the same
  endpoint or upstream, a shared tenant id, a local or unrecognized proxy
  with no declared `upstream:`, and an unresolved identity. Each warning
  prints a `two-key: WARNING:` line and is recorded in `constitution_loaded`
  (`judge_agent_separation.warnings`). The checks are
  `same_address_one_side_keyless`, `same_model_same_address`,
  `same_model_shared_route` (was the refusal `same_model_same_upstream`),
  `same_model_unknown_proxy` (was `same_model_unknown_upstream`),
  `shared_tenant`, and `unresolved_identity` (once per identity).
  `upstream:` and `tenant:` change which warnings print, never what is
  refused. `allow_same_model_distinct_tenant` is now a deprecated no-op,
  like `allow_same_provider_judge`.

  At call time a judge whose credential equals `agent_session` abstains
  (`cloud_judge_reused_agent_session`) wherever it connects, as in 0.2.1.
  An `agent_session` that is not a string now abstains (`agent_session must
  be a string`) instead of skipping the check.
- **"vendor" is renamed "maker" (#44).** A judge's maker is who made its
  model, as the operator labels it (default: its `provider`), not
  verified, and never compared with the monitored agent. Judge key
  `vendor:` → `maker:`; quorum key and field `min_vendors` → `min_makers`;
  `Judge.vendor` → `Judge.maker`; the `vendor=` argument of `LLMJudge` and
  `FixedJudge` → `maker=`; `Judge.describe()` key `vendor` → `maker`; the
  deny and start-up refusal `insufficient_vendors:` →
  `insufficient_makers:`. The old names still work in 0.2.2, with one
  stderr line each, and are removed in 0.2.3. A judge class written before
  the rename that overrides `vendor`, sets the private `_vendor`, or is a
  duck-typed object with a `vendor` attribute keeps that label as its maker.
  `QuorumPolicy.to_record()` writes `min_makers`, so `policy_digest`
  changes for the same settings; `audit.check_decision_digests` recomputes
  from each stored record, so older ledgers still check clean.
- **Password fingerprints use scrypt.** A username and password pair is
  fingerprinted with scrypt (N=2^17, r=8, p=1, the OWASP minimum: 128 MiB,
  about 0.4 s per pair at start-up) under the per-install key as the salt
  (`scrypt-n17-r8-p1:...`), and only with that key. API tokens keep
  HMAC-SHA256: they are random, so a cheap hash is safe. The per-install key
  sits beside the ledger key, so anyone who can decrypt the ledger holds it
  too; for a guessable password only the scrypt cost slows an offline
  guess. This clears the two high CodeQL alerts
  (py/weak-sensitive-data-hashing) the new password support raised.
  `constitution_loaded` records `password_alg` beside `alg`.
- `quorum` passes a judge's `score_bound` the keyword arguments its
  signature accepts, instead of retrying on `TypeError`, so a `TypeError`
  inside a judge is an abstention, not a second call without the agent
  session. A signature that cannot be read gets every keyword.
- The build requires `setuptools>=77.0`, the first release that accepts
  `license = "Apache-2.0"` as an SPDX string (PEP 639).

### Added

- **HTTP Basic auth, over HTTPS only.** `auth: {type: basic, username_env:
  ..., password_env: ...}` on a judge or in `agents.yaml`, and
  `username_env` / `password_env` instead of `credential_env` in
  `monitored_agent:`. A plain-HTTP `base_url` with Basic auth is refused, and
  so is a username containing `:`. The old `username_password` type is
  still refused, with a message naming `basic`. OAuth device-code is still
  refused.

### Fixed

- **#29**: credential and start-up identity errors use `type_tag(e)` (at
  most 32 characters) instead of the raw `type(e).__name__`, and the LLM
  judge `credential:` abstain is capped with `cap_ledger_text`.
- **#42**: `ToolGateway._locks` no longer grows with every redeemed jti.
  Each entry is reference-counted under `_locks_guard` and removed when the
  last thread that holds or waits on it leaves, including after a tool
  exception or a lock-file error. No LRU cap, so a held lock is never
  evicted. The lock files under `<ledger>.redeem-locks/` are unchanged (one
  per jti, never deleted).
- A judge class whose `vendor` property calls `super().vendor` no longer
  recurses.
- A shared-credential refusal says what to do for a placeholder a local
  server ignores (`EMPTY`): give each side its own value, or leave it off
  one side (`auth: {type: none}` on a judge, `credential: none` on the
  agent); on one address, give the judge its own address or a credential
  the server checks.

### Docs

- `revoke` is described as what it does (#46): it ends tokens issued before
  the call; it does not stop new approvals and does not survive a restart.
  HOWTO's "Stop" section is now "Revoke outstanding tokens".
- Security findings are taken as public issues while this is a prototype
  (SECURITY.md, AGENTS.md); private reporting starts once the product is
  more mature and in use. The review findings are issues #45 to #60.
- README and HOWTO describe a gateway in its own process or host (#45),
  marked designed, not yet built, and what happens today with a `Ledger`
  opened in another process.
- HOWTO "If the ledger will not open after a crash" (#49): a manual
  recovery, checked against a ledger with uncovered entries and a torn
  line. A recovery command is still open.
- The witness key is described as it is: the head carries its own witness
  public key, which is not pinned (#58), so the principal key and the
  ledger key together can sign a head. Pinning is planned for 0.2.3.
- The identity docstring and HOWTO no longer claim the per-install
  fingerprint key stops a ledger reader from testing guesses.
- New `ROADMAP.md` (0.3 key backup through 1.0) and the README roadmap
  table; SCOPE and THREAT_MODEL "planned" sections; AGENTS.md puts PKI,
  hybrid ML-DSA, and a FIPS approved mode in scope for this repository
  (owner's uploads). ROADMAP 0.2.x: 0.2.2 carries the two owner decisions
  above; features freeze after it.
- THREAT_MODEL describes the claimed-field problem in plain words and what
  the ledger holds (proposal text, derived form, reasons, digests, sizes;
  never raw bytes of an oversized or dropped value; never keys).
- Module docstrings and comments no longer cite notes or a repository
  outside this one, or the 5.2/5.4 section numbers of an outside document.
  Eight "§4" or "section-4" citations remain (#59). `QuorumPolicy.section4`
  keeps its name.
- The source distribution includes `examples/`, which one test reads. The
  install lines include the `[yaml]` extra.
- README layout table: rows for `action.py`, `agent_meta.py`,
  `canonical.py`, `constitution.py`, and `testing.py`. Test skip messages
  name `pip install two-key-concept[yaml]`. CHANGES is oldest first.

### Upgrading from 0.2.1

1. **Setups that started and now refuse** (`judge_matches_agent:` or
   `credential could not be read at start-up`):
   - a keyless judge and a keyless agent on one `host:port`, whatever
     their models (for example two models on one Ollama daemon): serve the
     judge on another port or daemon, or give one side a credential;
   - an `agents.yaml` `ollama` agent with a configured key next to a
     keyless judge on its `host:port`: the agent never sends that key, so
     both count as keyless (same fix);
   - an `agents.yaml` local agent whose configured key cannot be read:
     set the variable, or remove `auth:`.
2. **Setups that refused and now start with warnings**: the same model on
   the same endpoint or upstream, a shared tenant id, a local proxy with no
   `upstream:`, an unresolved identity. Read the `two-key: WARNING:` lines
   at start-up, or `judge_agent_separation.warnings`. Alerts that matched
   `same_model_same_upstream` or `same_model_unknown_upstream` should
   match `same_model_shared_route` and `same_model_unknown_proxy`.
3. Rename `vendor:` to `maker:` and `min_vendors:` to `min_makers:` in
   judges.yaml, and `vendor=`, `.vendor`, `min_vendors=` to `maker=`,
   `.maker`, `min_makers=` in Python. The old names work in 0.2.2 and are
   removed in 0.2.3. Giving both names is refused (`not both`), and so is
   `dataclasses.replace(policy, min_vendors=...)`, because `replace` also
   passes the current `min_makers`.
4. Alerts or scripts that match `insufficient_vendors` should match
   `insufficient_makers`; code that reads `Judge.describe()["vendor"]`
   should read `"maker"`.
5. `policy_digest` changes for the same settings, and `identities_digest`
   changes where a side now counts as keyless or uses Basic auth. Compare
   digests within one `constitution_loaded`. The `judge_agent_separation`
   record has `checks` `[same_credential, same_address_no_credential]` and
   new keys `same_agent`, `warning_checks`, and `warnings`. The
   `judge_matches_agent:` message text changed.
6. Remove `allow_same_model_distinct_tenant` when convenient; it does
   nothing.
7. Pass `agent_session` as a string. Anything else now makes each judge
   abstain.
8. `two_key.identity` no longer has `distinct_tenants`,
   `same_model_overlap`, `TENANT_OPTIN_WARNING`, or `TENANT_OPTIN_FLAG`.
9. Building from source needs `setuptools>=77.0`.

### Reviews

- The code-review skill on `main...working` (15 findings, 10 fixed, the
  rest documented or left by design), two adversarial review workflows on
  the judge rule (25 findings, 14 confirmed, none a way past the rule), and
  a release-readiness check (packaging, release docs, regressions against
  0.2.1, CodeQL, process). CodeQL on PR #61 found the password-hashing
  issue fixed above. All were run by an AI assistant in this session.
- Maintainer security review (AGENTS.md): the owner signed off on
  2026-10-09, accepting those reviews and the scrypt fix instead of a
  line-by-line review.

### Still open

- Issues #45 to #60 are Low or Info. #58 (the witness public key is not
  pinned) is rated Low by the owner and is planned for 0.2.3. #49's
  recovery command, #46's persistent halt, and #45's gateway-only ledger
  role are not built.

### Planned for 0.2.3

- Pin the ledger's witness public key (#58); see ROADMAP 0.2.x.
- Remove the `vendor` / `min_vendors` aliases (breaking): every
  `TODO(remove-vendor-alias)` site.
