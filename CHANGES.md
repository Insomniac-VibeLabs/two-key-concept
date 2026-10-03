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




