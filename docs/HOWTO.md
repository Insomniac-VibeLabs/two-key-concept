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

`init-key` writes `principal.pem` with mode 0600 (created that way, never
chmodded afterwards) and refuses to overwrite an existing key. Commands that
take `--key` refuse a key file that the group or others can read
(`key_file_insecure`) or that is a symlink.

The signature covers the prose, the hard rules, and `tool_specs`. A modified
file will not load. `tool_specs` is required. A bare rule list, a missing
key, `null`, and an empty mapping are refused. `examples/hard_rules.yaml`
has a spec for every allow-listed tool. Amount, counterparty, and
irreversible are read from the argument bytes, and a claim that disagrees
is a deny. `data_class` is the stricter of the claim and the tool's
`data_class_floor`. This package does not classify free text. A tool that
carries text the rules must treat as sensitive needs that class as its
`data_class_floor`. A missing amount path, a non-numeric amount, or a
currency other than `usd` on `pay_bill` is a deny. A value that cannot be
read at all is a `derive_failed` deny: `derive_failed:amount_unreadable`
for an amount such as `10**400`, `derive_failed:value_unreadable:<Type>` for
any other value.

A key the spec does not name does not change the form and does not reach
the tool. The spec does not have to list every nested key. `deny_unmapped`
defaults off: the call can still allow, and the gateway drops the unnamed
key. The ledger records the names of dropped keys (`dropped_keys`), never
their values. Set it true to deny that key (`unmapped_field`). `payload`
names a value that may be present and is not interpreted. A payload path
may not equal, contain, or sit under an amount, currency, or counterparty
path, compared without regard to case (`TO.name` overlaps `to.name`);
such a spec does not load. With no `shape`, that
path covers the value and its children. `shape` is optional: `string`,
`number`, or `list` (a list of strings). `max_length` bounds a string or
a list. A nested value, a boolean, or a too-long value is
`payload_shape`. Shape does not read the contents. Classification of what
the text means is left to Path B, or to DLP in the full `two-key`
repository.

A counterparty path must include `allow`, a non-empty list of strings. A
party that is not on that list is `counterparty_not_allowed`. The tool
receives the canonical party (trimmed, lower case), not the raw spelling.
`examples/hard_rules.yaml` allows `ada@example` on the mail tools and
`power-co.example` on `pay_bill`. Those mail tools name `subject` and
`body` as strings (`max_length` 200 and 8000). The words are not read. A
field that is neither a control path nor a payload path is dropped. A
blocked party still denies through `deny_counterparties` when one is present.

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

## The monitored agent and the judge-is-not-the-agent rule

The minimum is one judge, and no judge may be the monitored agent. Declare
the agent yourself, never from what the agent reports: the
`monitored_agent:` block in judges.yaml (the CLI reads it), or
`TwoKey(monitored_agent=...)` with a mapping, an `AgentDeclaration`, a
`MonitoredAgent`, or a list of them. Give `model`, `provider` (a label,
recorded and never compared), `base_url`, and either `credential_env` (the
name of the environment variable holding the agent's key) or
`credential: none` for a keyless loopback or private agent. Optional keys
are `id`, `tenant`, and `upstream`; any other key is refused. Without a
declaration, `TwoKey` refuses with `monitored_agent_required:`.

At startup each judge and agent is resolved to:

- a normalized model id: NFKC first, Unicode dashes folded to `-`,
  zero-width characters removed, lower case, then router prefixes, dated
  snapshot suffixes, `-latest`, Vertex `@` versions, Bedrock `-v2:0`,
  Ollama `:latest`, Azure's `gpt-35`, and a few aliases removed or mapped;
- the endpoint `host:port` of `base_url`. Every name or address of this
  machine is written `localhost`: loopback names and addresses (including
  `127.1`), `localhost.localdomain`, `0.0.0.0` and `::`, and the machine's
  own host name and addresses. Other hosts are compared literally by
  `host:port`;
- the upstream that serves the model, and how it was found
  (`resolved_by`): `endpoint` (a direct provider host, Azure OpenAI, or a
  known inference host), `model_prefix` (a recognized router, a local
  server, or an unknown host where the model id names its maker, such as
  `openai/gpt-4o` or `qwen2.5:7b`), or `declared_upstream` (your
  `upstream:` key). `model_prefix` is operator-attested through the model
  name and is not verified. A model id ending in `:cloud` or `-cloud`
  adds `ollama.com` and is never local;
- tenant ids, each scoped by provider family: the Azure resource and
  deployment and the Vertex project read from the URL, plus a `tenant:`
  mapping you declare with any of `organization`, `project`, `account`,
  and `deployment` (for example `tenant: {organization: org-123}`). A
  Bedrock `account` is scoped by the region in the host. Elsewhere a
  declared id is scoped by the provider family: the endpoint's (`openai`,
  `anthropic`, `ollama`, ...), or for a proxy on a local or unrecognized
  host the family of its declared `upstream:`, its Ollama cloud model, or
  its model maker, never the proxy's own address. So `project: p1` behind a
  local proxy to OpenAI is the same tenant as `project: p1` at
  api.openai.com;
- a credential fingerprint: HMAC-SHA256 of the key with surrounding
  whitespace stripped, under a per-install key,
  `<ledger>.ledger-key/fingerprint.key` (32 random bytes, created once with
  O_EXCL, mode 0600). Raw keys are never logged.

`TwoKey` refuses with `judge_matches_agent:` only when a judge is the same
agent:

- the same credential fingerprint;
- a shared tenant id;
- the same normalized model on the same endpoint `host:port`;
- the same normalized model where either side is a loopback or private
  endpoint (a LiteLLM-style proxy or a local daemon, with or without a key)
  that declares no `upstream:`. Such an endpoint can forward the agent's
  model to the agent's provider and account, so its upstream and tenant are
  unknown. Any host that is not a recognized vendor, router, or inference
  host counts the same way, whatever the model's `maker/` prefix says (for
  example `litellm`, `host.docker.internal`, `proxy.corp.example`, 100.64.x,
  or 169.254.x). A local daemon serving its own weights declares its own
  address (`upstream: localhost:11434`);
- the same normalized model reaching the same upstream: declared upstreams
  count as endpoints, and an Ollama cloud model (`:cloud`, `-cloud`) reaches
  `ollama.com` even through a local daemon. This is
  `same_model_same_upstream`, and declared tenants do not lift it. Two
  accounts on one upstream serving one model are still that model from that
  provider, as in two-key. Upstreams are compared as lower-case `host` or
  `host:port` with the default port removed;
- or either side is unresolved: an unrecognized host or router whose model
  names no maker, or a loopback or private endpoint (a local proxy such as
  LiteLLM) whose model is an alias with no recognizable maker. Declare
  `upstream:` (a host or a list, for example `upstream: api.anthropic.com`)
  to attest where such a proxy routes. It is recorded, not verified.

The same provider or upstream with a different model, the same endpoint
with a different model, the same model through another endpoint (for
example a router) with another key and tenant, a local proxy that declares
a non-overlapping upstream (a different provider, `upstream: api.groq.com`),
a different daemon, and the same provider on another model or endpoint are
allowed and recorded
(`same_provider: allowed`). `allow_same_provider_judge` is accepted, prints
a deprecation note, and has no effect.

`quorum: allow_same_model_distinct_tenant: true` is a logged opt-in, off by
default. With it, the same model on the same endpoint or upstream is
allowed only when all of these hold:
- both sides declare `tenant:`;
- the scoped tenant ids are non-empty and share nothing;
- both sides have a key, and the fingerprints differ.

A keyless side (such as a local daemon), an undeclared tenant, a local proxy
with no `upstream:`, and an unresolved side are still refused. The flag:
- prints `two-key: WARNING: allow_same_model_distinct_tenant is set: ...` on stderr;
- records `same_model_tenant_optin: true` and
  `same_model_tenant_optin_pairs` (agent, judge, model, and both tenant
  labels) in `constitution_loaded`;
- is in `quorum_policy`, so it is part of `policy_digest`.

Tenants are declared, not verified. A misspelled key is refused as
`unknown quorum keys`.

Judge credentials are read at startup for this check, so a judge key that
cannot be read refuses to start. The result is the `judge_agent_separation`
field of the `constitution_loaded` ledger entry: every resolved identity
(fingerprints only), the fingerprint scheme and key id, and
`identities_digest`. The entry also holds the full quorum policy
(`quorum_policy`) and its `policy_digest`. Each `decision` entry carries
`identities_digest` and `policy_digest`, not the full policy. To check
them, `two_key.audit.check_decision_digests(ledger)` recomputes both from
the latest `constitution_loaded` before each decision and returns a list of
mismatches (empty when all match). By hand: `identities_digest` is
`canonical_hash({"agents": sep["agents"], "judges": sep["judges"]})` and
`policy_digest` is `canonical_hash(quorum_policy)`, with `canonical_hash`
from `two_key.canonical` (SHA-256 of sorted-key, compact, ASCII JSON).

At call time, a judge that is not on a loopback host makes the round deny
when `authorize` gets no `agent_session` (`cloud_judge_session_required`).
Any judge whose credential equals that session (whitespace stripped)
abstains with `cloud_judge_reused_agent_session`, and the round denies.

The in-process placeholder agent `two_key.testing.TEST_AGENT` is accepted
only with `allow_test_doubles=True` and only when every judge is a test
double (`in_process_agent_refused`).

## Quorum policy

The default needs one judge and has no diversity floors: `min_vendors: 1`,
`min_local_judges: 0`, `require_local_yes: false`. When `required_yes` is
not set (in `QuorumPolicy()`, the quorum block, or `TwoKey` with no policy),
it is `min(2, number of judges)`.
`QuorumPolicy.without_diversity_floors()` is **not** that default: it sets the
same floor values but defaults `required_yes` to 2. Prefer `QuorumPolicy()`
(or omit / set `required_yes` to `null`) for the one-judge default threshold.

`profile: high_assurance` in the quorum block, or
`QuorumPolicy.high_assurance()`, turns on two vendors, one local judge, and
a yes from a local judge. Use it for destructive, irreversible, financial,
or external-send tools. `examples/judges.yaml` meets it with the cloud hooks
plus local Qwen. Other quorum keys still apply on top of the profile.
`require_local_yes: true` with no local judge does not start
(`require_local_yes_without_local_judge`). Vendor names are compared after
NFKC and case folding, so `OpenAI` and `openai` are one vendor.

`TwoKey` does not start with no judge, with `timeout_seconds: null` (Path B
needs a hard deadline), or with two judges that share an id
(`duplicate_judge_id`). Judges run in parallel under that deadline; a judge
that errors, abstains, times out, or returns anything but a valid ballot is
not a yes. Ballots are paired with judges by position, and the judge id and
provider on the record come from the judge, not the ballot. A ballot that
names another judge abstains (`judge_id_mismatch`).

Without a local judge, the constitution prose, the action record, and any
attached tool arguments go to the cloud judges' vendors.

`require_path_a_first` stays off unless you set it. `TwoKey.authorize` does
not read it. Both paths still run. After a derive deny, judges do not
receive the argument bytes unless the quorum block sets
`tool_args_on_derive_deny: true`. Other denies still attach non-empty
arguments. `min_distinct_providers` still defaults to 1, so that count is
not itself a floor.

## Local judges

A judge counts as local only when `local_weights` is true and its
`base_url` host is on an explicit allowlist: `localhost`, 127.0.0.0/8,
::1, the RFC 1918 ranges (10/8, 172.16/12, 192.168/16), or IPv6
unique-local fc00::/7. Documentation, benchmark (198.18/15), reserved,
CGNAT (100.64/10), link-local (including 169.254.169.254), and NAT64
(64:ff9b::/96) addresses are not local, even where Python's `is_private`
says so. A DNS name other than `localhost` is not local. Ollama defaults
`local_weights` from the host, so a remote Ollama is not local, and a
model id ending in `:cloud` or `-cloud` (an Ollama cloud model) is cloud
and never local for every judge class, including an OpenAI-compatible
judge pointed at a local Ollama `/v1`, even on loopback. Plain
HTTP to a host other than `localhost`, `127.0.0.1`, or `::1` is refused
unless the judge sets `allow_insecure_http`. A judge on a LAN address is local for the quorum
floors but not loopback, so it still needs the agent session at call time.

## Parsing and limits

Every JSON and YAML document is parsed strictly: the signed constitution,
the rules file, judges.yaml and agents.yaml (JSON or YAML), the
`monitored_agent:` block, judge ballots, provider responses, agent
proposals, `--args`, and token payloads. A key repeated in one mapping, at
any depth, is refused with `duplicate key '<k>'`; it never resolves
last-one-wins. JSON `NaN` and `Infinity` are refused too (a ballot with
them is malformed and abstains). YAML still loads with a safe loader.

judges.yaml accepts only the top-level keys `judges`, `quorum`, and
`monitored_agent`; agents.yaml only `agents`. Anything else (a typo such as
`quorm`) is refused.

The action claim (the `tool`, `amount_usd`, `data_class`, ... mapping) is
measured before it is read: over 64 KiB of UTF-8 JSON it is denied
(`action_too_large`) and the ledger keeps only `action_size`,
`action_digest`, and `action_omitted: true`. A tool name is an identifier
of at most 128 characters (`a-z`, `0-9`, and `_ . : / -` after case
folding). A `malformed_action:` reason names the field, never its value or
an unknown key's name (`malformed_action:unknown action fields (2)`,
`malformed_action:data_class: not a known class`).

Tool arguments or a proposal over 256 KiB of compact UTF-8 JSON are denied
before anything reads or ledgers them (`args_too_large`, `proposal_too_large`).
The arguments are encoded once: the canonical bytes settle the cap (they are
never shorter than the UTF-8 measure), give the hash the token binds, and are
re-measured exactly only when they are over the cap. The gateway does the same.
The ledger keeps only `tool_args_size`, `tool_args_digest`, and
`tool_args_omitted: true` (or the `proposal_` equivalents). Arguments
nested too deeply to encode are denied in `authorize` and at the gateway
with `invalid_call:tool args are nested too deeply`; the ledger keeps
`tool_args_omitted: true` and `tool_args_error`. Encoding runs before the
size check, so the reason is the same on Python 3.10, 3.11, and 3.12.

Each input (tool args, the action claim, the proposal) is first copied once
into built-in types (`canonical.to_plain`). Any Mapping becomes a dict and a
tuple becomes a list. The size cap, the token's hash, the judges, the ledger
and the tool all read that copy, never a custom type's `str()` or `repr()`.

"Too deeply" means more than 62 levels of objects and arrays
(`canonical.MAX_INPUT_DEPTH`). The encoder itself allows 64
(`canonical.MAX_DEPTH`) and counts without recursion. The two spare levels
are the ones an input gains inside a ledger entry or a judge's record
(`raw.tool_args`), so arguments at exactly 62 still encode there. The
action claim (usually `raw`) and a structured proposal have the same limit.
One level more is `malformed_action:action claim is nested too deeply` or
`malformed_proposal`, and it is ledgered.

If a ledger body still cannot be encoded, `Ledger.append_bounded` writes
the entry anyway. It keeps the body's short scalar fields (reason, jti, tool, allowed), always retains `policy_digest` and `identities_digest` when present, plus `body_size`, `body_digest`, `body_omitted: true`, and `body_error`.

The token lifetime (`TwoKey(ttl_seconds=...)`, `--ttl-seconds`) is an
integer from 1 to 300 seconds; anything else, including a float, NaN, or
infinity, refuses to start (`ttl_out_of_range:`). A token whose time fields
are not finite numbers is `malformed_token`.

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
Fill in the `model:` lines and the `monitored_agent:` block of
`examples/judges.yaml` first, and set the judge key variables.

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
  --agent-session-env OPENAI_AGENT_API_KEY \
  --emit-token ./token.txt
```

The bearer token is never printed. The output shows `token_jti` and
`token_digest` (the ledger's `capability_issued.token_hash`).
`--emit-token PATH` writes the token itself to a new file with mode 0600
and refuses to overwrite one. `--agent-session-env NAME` names the
environment variable that holds the agent session; the old
`--agent-session VALUE` took the secret on the command line and is
refused. `--ttl-seconds` sets the token lifetime, 1 to 300 seconds
(default 120). `--args` is parsed strictly before anything else is loaded.
The decision entry records `origin: cli`.

`--data-class` defaults to `classified`, and `--irreversible` defaults to
true. Those are the same fail-closed defaults as a missing field in
`normalize_action`. The command above sets public and reversible so the
example rules allow a draft. `--no-irreversible` is the off switch.

Exit status is 0 on allow and 2 on deny. The ledger records and the head
are ciphertext. The append lock is `<ledger>.lock` next to the ledger
directory. Redemption locks are `<ledger>.redeem-locks/` there too, not
inside the ledger directory. First open writes `<ledger>.ledger-key/ledger.key` and
`<ledger>.witness/witness.pem` next to the ledger directory, not inside it.
Both are created with O_EXCL at mode 0600; a ledger key that is group- or
world-readable, a symlink, or not 32 bytes is refused (`ledger_key_insecure:`
or `ledger_key_unreadable:`).
The authorize command does not accept test-double judges.

## Authorize from Python


```python
from pathlib import Path
from two_key.constitution import load_envelope, verify_signed
from two_key.core import TwoKey
from two_key.judges.config import load_config_file
from two_key.identity import load_monitored_agent_file
from two_key.keys import load_private_key_file
from two_key.ledger import Ledger
import os

key = load_private_key_file("keys/principal.pem")
judges, policy = load_config_file(Path("examples/judges.yaml"))
agent = load_monitored_agent_file(Path("examples/judges.yaml"))
ledger = Ledger("ledger", key)
tk = TwoKey.load(ledger, key.public_key(), load_envelope("constitution.signed.json"),
                 judges, private_key=key, quorum=policy, monitored_agent=agent)
decision = tk.authorize(
    {"tool": "email_draft", "amount_usd": 0, "data_class": "public", "irreversible": False},
    {"to": "ada@example"},
    "draft a status note",
    agent_session=os.environ["OPENAI_AGENT_API_KEY"],
)
```

`decision.token` is set only when both paths allow and the signed ledger
head was written. `decision.to_record()` leaves the token out and gives
`token_jti` and `token_digest`, so it is safe to print or log. Any
exception inside `authorize` is a deny (`internal_error:<Type>`) written to
the ledger. The gateway is the only component that should call the tool.

## Monitored agents

`examples/agents.yaml` configures Grok, ChatGPT, Claude, Gemini, and a local
model. Hosting is recorded. It is not trust.

`authorize_from_agent` parses the proposal (`tool`, `arguments`, `proposal`,
and optional structured fields) and runs both paths. It does not call the
tool. Extra keys in the proposal are rejected. Text longer than 1,048,576
characters (four times the arguments cap) is denied `proposal_too_large`
before it is parsed. Text that is not a string, is not JSON, has a repeated
or extra key, or misses a field is denied `malformed_proposal`. Both denies
are ledgered with the text's size and digest only; the reason names no key.

Use a different API key for agents than for judges. Pass the agent object
you run as `TwoKey(monitored_agent=agent)`; it is checked against every
judge at startup like the judges.yaml declaration. A proposal with a
repeated JSON key, at any depth or inside an `arguments` string, is
refused.

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
`capability.pub.pem` beside it. The key is created once with mode 0600 in a
0700 directory. After a token has been issued it is never regenerated: a
missing or different key refuses to start (`capability_key_missing`,
`capability_key_changed`), and so does a ledger with issued tokens but no
pinned key fingerprint (`capability_key_unpinned`). A capability key equal to the principal key is
refused. The principal key on the ledger signs the head. A token signed
with that principal key does not redeem.

The gateway checks the signature, expiry, a lifetime no longer than the TTL
(`ttl_too_long`), an issue time no more than 5 s ahead
(`issued_in_future`), missing time or binding fields (`malformed_token`),
the tool, argument hash, constitution hashes, spec hash, the recomputed
form, the ledger prefix root, the capability key fingerprint pinned in the
ledger (`capability_key_mismatch`), and that nothing revoked or reloaded
the constitution after issuance. A token that fails its signature or
format check is refused without a ledger entry, so an unauthenticated
caller cannot write to the ledger. Any later refusal of an authenticated
token is ledgered as `gateway_denied` with the reason, the jti, the tool
name (only a short identifier; otherwise its size and digest), and
`tool_args_size` and `tool_args_digest`, never the argument values. Pass the same
argument object you authorized. The hash covers those bytes. The registered
function is called with declared paths only: unnamed keys are omitted, and
a counterparty path is the canonical party. The token is
single-use. A tool exception does not consume it, so the same token can be
retried. There is no content scanner on the way in or out.

Username/password and OAuth device-code auth are rejected. Use `env`,
`keyring`, or `callback`.

A redemption intent is checkpointed before the tool runs. A crash after that
intent, including after the tool has returned, does not run the token again.
A tool exception appends an abort and leaves the token usable. A crash before
the tool runs also blocks a retry.

## Known trade-offs by configuration

Each line is a trade-off that depends on how you configure Two-Key, and
names the setting or declaration that controls it.

- Declared `upstream:` labels are folded before match (NFKC, zero-width stripped,
  Unicode dashes to ASCII, casefold). Bare maker names such as `openai` map to the
  maker's API host (`api.openai.com`).
- Omit `tenant` when there is none; an empty mapping `tenant: {}` is refused.
- Declared `upstream:` and `tenant:` values are trusted as declared, not
  verified. A false declaration on a proxy can hide that it forwards with
  the agent's account and key. The same model through another endpoint is
  accepted by design when upstreams do not overlap.
- A maker prefix in a model id (`mistral/gpt-4o`) names the maker, not the
  host that serves it. On a host that is not a recognized vendor, router,
  or inference host (or any local alias), the same model as the agent is
  refused (`same_model_unknown_upstream`) unless that side declares an
  `upstream:` that is not the agent's.
- A local daemon serving its own weights is refused against the same model
  until you declare its own address (`upstream: localhost:11434`).
- A private-address `base_url` (RFC 1918, fc00::/7) is treated as a local
  proxy, so it needs `upstream:` when it serves the agent's model.
- This machine's own addresses are read once per process. After an address
  change, restart before relying on how `base_url` hosts fold to `localhost`.
- A `tenant:` on a proxy is scoped by the provider family its `upstream:`
  reaches, not by the proxy's address.
- `allow_same_model_distinct_tenant: true` lets a judge run the agent's
  exact model on the same endpoint under a different declared tenant. It is off by
  default, warns at startup, and is logged as `same_model_tenant_optin` in
  `constitution_loaded` (load-time only; not re-checked on each authorize).
  Leave it off unless the accounts are separate.
- Two judges, or a judge and the agent, on the same endpoint and model are
  refused whatever their `tenant:`, unless that flag is set.
- The runtime agent is not matched against `monitored_agent:`. The
  declaration is what is compared.
- `agents.yaml` in the examples has no `tenant:` or `upstream:`. Add them
  when the agent runs behind a proxy.
- After a successful `gateway_denied` append for a given jti, further denies of that authenticated token still refuse but do not append another `gateway_denied`. The jti is remembered only after append+checkpoint succeed (so a failed ledger write can be retried); the in-memory set is LRU-capped (default 4096; `max_denied_jtis` is clamped to at least 1). Concurrent same-jti denies are single-flight: only one append runs at a time; waiters re-check and skip if already marked. Waiters use a timed wait (default 30 seconds; `deny_inflight_wait_seconds` on `ToolGateway`): on timeout they still deny fail-closed without marking and without fail-open, so a stuck ledger append cannot hang waiters forever. `ttl_seconds` still bounds how long a token can be presented.
- The gateway pins the capability key from the latest
  `constitution_loaded`. Reload the constitution or revoke to change it.
- `payload:` paths in a tool spec may overlap each other. Only overlap
  with control paths is refused.
- `dropped_keys` is checked against every declared path, so the cost grows
  with the size of a tool spec.
- `model:` ids are not length-capped before they are normalized. Keep them
  to real model names.
- `authorize(..., agent_id=, hosting=, origin=)` and `authorize_from_agent`
  treat those fields as operator/library metadata for the ledger, not
  agent-controlled claims. Each must be a `str` or omitted (`None`); after
  strip, longer than 256 characters is refused (`agent_metadata_too_large`).
  Non-str is `invalid_agent_metadata` (ledger `got: non_str`, never the raw
  type name). A non-Mapping `agent_meta` (`check_agent_meta_mapping`) is
  `invalid_agent_metadata` with `got: non_mapping` (field values stay
  `non_str`). The value is never ledgered on deny. Blank/`None` `origin`
  defaults to `library`. An agent process can still pass huge values into
  `authorize()`, which is why the cap exists. If a ledger body cannot be
  encoded on a path about to issue a token, the decision is
  `ledger_body_too_large` (fail closed).
- Quorum/judge ledger exception text and both Path A `vm_fault` paths (`VMFault` and generic `Exception`) are `type_tag: message` capped at 300 characters; oversize keeps a prefix plus a digest of the remainder (`exception_ledger_error` / `cap_ledger_text`). All `ledger_failed:` reason strings for a `LedgerError` (gateway `_record_deny`, gateway redemption, core authorize/`_deny`) cap the message the same way; non-`LedgerError` deny paths keep `type_tag` only. Canonical encoding refuses a non-JSON type with the fixed label `unsupported_type` (never raw `__name__`); authorize/gateway `invalid_call:` / `malformed_action:` suffixes from `EncodingError` also go through `cap_ledger_text`.
- A token's `iat`/`exp` are read with `float()`. Tokens minted here are
  always numeric, so this only matters for tokens from another issuer.
- Config errors from the CLI print a traceback. Check judges.yaml with a
  dry start.
- A `ttl_seconds` out of range is reported with the prefix
  `ttl_out_of_range:`.
- On Python 3.12, an agent reply nested past 62 levels parses and is
  `invalid_call`. On 3.10 and 3.11 it is `malformed_proposal`. Both deny.
- `agent_session` is the frozen session. The agent's key is not added to it
  (unlike two-key 3af9f0a).
- The ledger's own records are read with the standard JSON parser, not the
  strict one, because they are signed and hash-chained.
- `audit.check_decision_digests` on a ledger from before 0.2.0 reports the
  missing digests as mismatches. Start a new ledger, or read those as "pre-0.2.0".

Open items that no setting changes:
- Test gaps: the ledger's O_EXCL path, the case-folded control-path check,
  the audit self-check, and five bare `assertRaises`.
- Comments that still cite design notes not in the repository.
- Names that differ from two-key for the same concept.

## Stop

```python
tk.revoke("principal stop")
```

Outstanding tokens then fail at the gateway.
