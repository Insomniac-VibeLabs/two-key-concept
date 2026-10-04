"""Two-Key concept: a tool call runs only if Path A and Path B both allow.

``authorize_from_agent`` runs both paths once the call is well-formed and within limits,
and does not execute tools. A malformed or oversized call is an early deny before either path.
Hosting (local or cloud) is recorded and never treated as trust.

``TwoKey`` refuses to start (``TwoKeyConfigError``) with no judge, with no
Path B deadline, with duplicate judge ids, without an operator declaration
of the monitored agent (``monitored_agent_required:``), or when a judge
could be that agent (``judge_matches_agent:``; see identity.py).
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, asdict, replace
from typing import Any, Mapping

from .action import Action, ActionValidationError, normalize_action
from .canonical import EncodingError, canonical_bytes, canonical_hash, digest_hex
from .agents import MAX_PROPOSAL_TEXT_CHARS, AgentConfigError, parse_proposal
from .capability import (CapabilityIssuer, CapabilityKeyError, capability_key_fingerprint, open_capability_key,
                         valid_ttl)
from .compiler import CompiledConstitution, compile_both
from .constitution import Constitution, ConstitutionError, verify_signed
from .identity import (AgentDeclaration, IdentityError, SeparationReport, check_separation, fingerprint_key_id,
                       configured_agent_identity, judge_identity)
from .derive import (MAX_ACTION_BYTES, DeriveError, args_size, args_too_large, blocked_from_rules, canonical_too_large,
                     derive, disagreement, disallowed_party, dropped_keys, form_for, size_record)
from .ledger import LedgerError
from .policy_vm import PolicyVM
from .quorum import QuorumPolicy, check_judge_set, convene


class TwoKeyConfigError(ValueError):
    """Two-Key refuses to start with this configuration."""


_DERIVE_DENIALS = {"amount_mismatch", "counterparty_mismatch", "irreversible_mismatch"}


def _derive_deny(reason: str | None) -> bool:
    return bool(reason) and (reason.startswith("derive_failed:") or reason in _DERIVE_DENIALS)


@dataclass
class Decision:
    allowed: bool
    reason: str
    token: str | None
    path_a: dict
    path_b: dict
    ledger_size: int
    agent: dict | None = None

    @property
    def token_jti(self) -> str | None:
        """The token id, read from the token body (not verified here; the gateway verifies)."""
        if not self.token:
            return None
        try:
            import base64
            from .strict import loads_json
            body = self.token.split(".")[1]
            return loads_json(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)))["jti"]
        except Exception:
            return None

    @property
    def token_digest(self) -> str | None:
        """``capability_issued.token_hash`` in the ledger. Safe to print; it cannot be redeemed."""
        return canonical_hash(self.token) if self.token else None

    def to_record(self) -> dict:
        """A printable record. The bearer token is replaced by its jti and digest; use ``.token``."""
        rec = asdict(self)
        rec.pop("token")
        rec["token_jti"], rec["token_digest"] = self.token_jti, self.token_digest
        return rec


class TwoKey:
    def __init__(self, ledger, public_key, constitution: Constitution, judges: list, *,
                 private_key=None, quorum: QuorumPolicy | None = None, ttl_seconds: int = 120,
                 allow_test_doubles: bool = False, clock=None, monitored_agent: Any = None):
        if not allow_test_doubles and any(getattr(j, "is_test_double", False) for j in judges):
            raise ValueError("test-double judges refused; pass allow_test_doubles=True only for offline tests")
        if not constitution.specs_enforced:
            raise ConstitutionError("tool_specs required")
        self.ledger = ledger
        self.public_key = public_key
        self.private_key = private_key
        self.constitution = constitution
        self.compiled: CompiledConstitution = compile_both(
            constitution.prose, constitution.hard_rules, constitution.tool_specs,
            specs_enforced=True)
        self.vm = PolicyVM(self.compiled.bytecode)
        self.judges = list(judges)
        if not self.judges:
            # Fail closed: with no judge, Path B can never turn its key.
            raise TwoKeyConfigError("no_judges: configure at least one Path B judge")
        judge_ids = [getattr(j, "judge_id", None) for j in self.judges]
        if any(not isinstance(i, str) or not i for i in judge_ids) or len(set(judge_ids)) != len(judge_ids):
            # Ballots are matched to judges by id; a shared id lets one judge's ballot stand in for another's.
            raise TwoKeyConfigError("duplicate_judge_id: judge ids must be unique, non-empty strings")
        self.quorum = (quorum or QuorumPolicy()).resolved(len(self.judges))
        if self.quorum.timeout_seconds is None:
            # Fail closed on a hung judge: every round ends by the deadline, and a late judge abstains.
            raise TwoKeyConfigError("Path B needs a hard deadline: quorum timeout_seconds must be a positive "
                                    "number, not None")
        check_judge_set(self.judges, self.quorum)
        # Judge != monitored agent, from operator configuration only (identity.py).
        self.separation = self._check_separation(monitored_agent, allow_test_doubles)
        # The resolved identities are written once, in constitution_loaded; every decision entry
        # carries the policy in effect and the digest of those identities (identities_digest).
        sep = self.separation.to_record()
        self._identities_digest = canonical_hash({"agents": sep["agents"], "judges": sep["judges"]})
        sep = {**sep, "identities_digest": self._identities_digest,
               "credential_fingerprint": {"alg": "hmac-sha256", "key_id": fingerprint_key_id(self._fp_key),
                                          "input": "secret with surrounding whitespace stripped"}}
        self._decision_context = {"policy": self.quorum.to_record(),
                                  "identities_digest": self._identities_digest}
        try:
            valid_ttl(ttl_seconds)       # an int in 1..MAX_TTL_SECONDS (300); NaN, inf, floats refused
        except ValueError as e:
            raise TwoKeyConfigError(f"ttl_out_of_range: {e}") from None
        self.ttl_seconds = ttl_seconds
        # The minting key is not the principal key, and it is not given to the gateway.
        # max_ttl_seconds: verify() refuses any token that lives longer than this TwoKey's TTL.
        self.issuer = None
        if private_key:
            try:
                cap_key = open_capability_key(ledger, public_key)
            except CapabilityKeyError as e:
                raise TwoKeyConfigError(str(e)) from e
            self.issuer = CapabilityIssuer(cap_key, clock=clock, max_ttl_seconds=ttl_seconds)
        self._clock = clock
        self.ledger.append("constitution_loaded", {
            "digest": constitution.digest,
            "bytecode_hash": self.compiled.bytecode_hash,
            "nl_hash": self.compiled.nl_hash,
            "spec_hash": self.compiled.spec_hash,
            "quorum_policy": self.quorum.to_record(),
            # The gateway pins this: a token key that is not this one does not redeem.
            "capability_key_fingerprint": (None if self.issuer is None
                                           else capability_key_fingerprint(self.issuer.public_key)),
            "judge_agent_separation": sep,
        })
        self.ledger.checkpoint()

    def _check_separation(self, monitored_agent: Any, allow_test_doubles: bool) -> SeparationReport:
        """Refuse to start if any judge could be the monitored agent. See identity.py."""
        if monitored_agent is None:
            raise TwoKeyConfigError("monitored_agent_required: declare the monitored agent (monitored_agent= "
                                    "with model, provider, base_url, and credential_env or credential: none) "
                                    "whenever judges are configured")
        decls = monitored_agent if isinstance(monitored_agent, (list, tuple)) else [monitored_agent]
        # A placeholder in-process agent proves nothing about a real judge, so it is accepted only
        # when every judge is a test double too (an offline test). With a real judge, declare the real agent.
        allow_in_process = allow_test_doubles and all(getattr(j, "is_test_double", False) for j in self.judges)
        try:
            self._fp_key = key = self.ledger.fingerprint_key()   # per-install HMAC key; fingerprints only
        except LedgerError as e:
            raise TwoKeyConfigError(str(e)) from e
        try:
            agents = []
            for d in decls:
                if isinstance(d, AgentDeclaration) or isinstance(d, Mapping):
                    if not isinstance(d, AgentDeclaration):
                        d = AgentDeclaration.from_mapping(d)
                    agents.append(d.resolve(allow_in_process=allow_in_process, fp_key=key))
                elif all(hasattr(d, k) for k in ("agent_id", "model", "base_url", "credential")):
                    agents.append(configured_agent_identity(d, key))  # a MonitoredAgent from agents.yaml
                else:
                    raise IdentityError("monitored_agent must be a mapping, an AgentDeclaration, or a MonitoredAgent")
            judges = [judge_identity(j, key) for j in self.judges]
            return check_separation(agents, judges, self.quorum.allow_same_provider_judge)
        except IdentityError as e:
            raise TwoKeyConfigError(str(e)) from e

    @classmethod
    def load(cls, ledger, public_key, envelope: dict, judges: list, **kw) -> "TwoKey":
        return cls(ledger, public_key, verify_signed(envelope, public_key), judges, **kw)

    def authorize(self, action: dict, arguments: dict, proposal: str, *,
                  agent_id: str | None = None, hosting: str | None = None,
                  agent_session: str | None = None, origin: str = "library") -> Decision:
        """Run both paths once the call is well-formed and within limits. Any exception is a deny that is written to the ledger (``internal_error:``).

        ``origin`` is recorded on the decision entry (the CLI passes ``"cli"``).
        """
        self._origin = origin if isinstance(origin, str) and origin else "library"
        try:
            return self._authorize(action, arguments, proposal, agent_id=agent_id, hosting=hosting,
                                   agent_session=agent_session)
        except Exception as e:  # fail closed: no exception reaches the caller as anything but a deny
            agent = None
            if agent_id or hosting:
                agent = {"id": agent_id, "hosting": hosting or "unspecified", "trusted": False}
            return self._deny(f"internal_error:{type(e).__name__}", agent, None, None)

    def _authorize(self, action: dict, arguments: dict, proposal: str, *,
                   agent_id: str | None = None, hosting: str | None = None,
                   agent_session: str | None = None) -> Decision:
        agent = None
        if agent_id or hosting:
            # Hosting is a deployment fact, not a trust decision.
            agent = {"id": agent_id, "hosting": hosting or "unspecified", "trusted": False}
        # The raw claim is measured before anything reads it: an oversized one keeps only size and digest.
        claim = action.to_record() if isinstance(action, Action) else action
        claim_size = args_size(claim)
        if claim_size < 0 or claim_size > MAX_ACTION_BYTES:
            return self._deny("action_too_large", agent, None, None, size_record(claim, "action"))
        try:
            normalized = normalize_action(action)
        except ActionValidationError as e:   # the message names the field, never its value
            return self._deny(f"malformed_action:{e}", agent, None, None)
        if isinstance(arguments, Mapping):
            # Freeze the arguments to the canonical bytes a token would bind, before the size check:
            # a value that cannot be encoded (nested too deeply, NaN, a non-string key) is
            # invalid_call on every Python version, not args_too_large where the sizer recursed out.
            try:
                frozen = canonical_bytes(arguments)
            except EncodingError as e:     # two-key's name: invalid_call:<why>, the same as the gateway's
                return self._deny(f"invalid_call:{e}", agent, None, None,
                                  {"tool_args_omitted": True, "tool_args_error": str(e)})
            # Encoded once: these bytes settle the size cap and give the digest the token binds.
            oversized = canonical_too_large(frozen, arguments)
            frozen_digest = digest_hex(frozen)
        else:
            oversized, frozen_digest = args_too_large(arguments), None
        # Before anything is derived, judged, or ledgered: only the size and digest are kept.
        if oversized:
            return self._deny("args_too_large", agent, None, None, size_record(arguments, "tool_args"))
        if args_too_large(proposal):
            return self._deny("proposal_too_large", agent, None, None, size_record(proposal, "proposal"))
        spec = None
        if self.compiled.specs_enforced:
            spec = self.compiled.tool_specs.get(normalized.tool)
        form = None
        claimed_data_class = normalized.data_class
        deny_reason = None
        if spec is not None:
            proposed: Mapping[str, Any]
            if isinstance(action, Action):
                proposed = action.to_record()
            elif isinstance(action, Mapping):
                proposed = action
            else:
                proposed = {}
            blocked = blocked_from_rules(self.compiled.rules)
            try:
                if not isinstance(arguments, Mapping):
                    raise DeriveError("arguments_not_object")
                derived = derive(spec, arguments)
            except DeriveError as exc:
                deny_reason = f"derive_failed:{exc.reason}"
                normalized = replace(normalized, data_class="classified", irreversible=True)
            else:
                mismatch = disagreement(proposed, derived)
                if mismatch:
                    deny_reason = mismatch
                form = form_for(derived, claimed_data_class, blocked)
                party = form["counterparty"] if derived.counterparties else normalized.counterparty
                normalized = replace(
                    normalized,
                    amount_usd=float(form["amount_usd"]),
                    data_class=form["data_class"],
                    counterparty=party,
                    irreversible=bool(form["irreversible"]),
                )
                if (
                    deny_reason is None
                    and disallowed_party(spec, arguments)
                    and not (set(derived.counterparties) & blocked)
                ):
                    deny_reason = "counterparty_not_allowed"
        path_a = self.vm.eval(normalized)
        path_a_rec = {"allowed": path_a.allowed, "reason": path_a.reason, "denied_by": path_a.denied_by}
        binding = {
            "action_hash": canonical_hash(normalized.to_record()),
            "constitution_hash": self.constitution.digest,
            "nl_hash": self.compiled.nl_hash,
            "bytecode_hash": self.compiled.bytecode_hash,
        }
        # From here both paths answer. A Path A deny does not skip Path B.
        # After a derive deny, judges do not receive the argument bytes unless
        # the quorum policy opts in. The normalized record still goes to Path B.
        judge_args: Mapping | None = arguments
        if _derive_deny(deny_reason) and not self.quorum.tool_args_on_derive_deny:
            judge_args = None
        quorum = convene(self.judges, self.compiled.judge_text, normalized, proposal,
                         self.quorum, binding, judge_args, agent_session)
        path_b_rec = {"passed": quorum.passed, "reason": quorum.reason,
                      "yes": quorum.yes, "no": quorum.no, "abstain": quorum.abstain}
        allowed = bool(path_a.allowed and quorum.passed and deny_reason is None)
        if deny_reason:
            reason = deny_reason
        elif allowed:
            reason = "both_paths_allow"
        else:
            reason = path_a.reason if not path_a.allowed else quorum.reason
        token = None
        try:
            self.ledger.append("proposal", {"tool": normalized.tool, "proposal": proposal, "agent": agent})
            if spec is not None:
                self.ledger.append("action_normalized", {
                    "tool": normalized.tool,
                    "form": form,
                    "claimed_data_class": claimed_data_class,
                    "deny_reason": deny_reason,
                    # Names of keys the tool will not receive. Never their values.
                    "dropped_keys": dropped_keys(spec, arguments),
                })
            self.ledger.append("path_a", path_a_rec)
            self.ledger.append("path_b", path_b_rec)
            if allowed:
                if self.issuer is None:
                    allowed, reason = False, "no_issuer_key"
                else:
                    issued = self.issuer.issue(
                        tool=normalized.tool, arguments=arguments, args_digest=frozen_digest,
                        ledger_root=self.ledger.merkle_root(), ledger_size=self.ledger.size(),
                        bytecode_hash=self.compiled.bytecode_hash, nl_hash=self.compiled.nl_hash,
                        spec_hash=self.compiled.spec_hash,
                        form=form, claimed_data_class=claimed_data_class if form is not None else None,
                        ttl_seconds=self.ttl_seconds)
                    token = issued.token
                    self.ledger.append("capability_issued", {"jti": issued.payload["jti"],
                                                            "token_hash": issued.token_hash,
                                                            "ledger_root": issued.payload["ledger_root"]})
            self.ledger.append("decision", {"allowed": allowed, "reason": reason, "agent": agent,
                                            "origin": getattr(self, "_origin", "library"),
                                            **self._decision_context})
            self.ledger.checkpoint()
        except LedgerError as e:
            return Decision(False, f"ledger_failed:{e}", None, path_a_rec, path_b_rec, self.ledger.size(), agent)
        return Decision(allowed, reason, token if allowed else None, path_a_rec, path_b_rec, self.ledger.size(), agent)

    def authorize_from_agent(self, agent, proposal_text: str, *, agent_session: str | None = None) -> Decision:
        """Parse an untrusted agent proposal, run both paths, and do not execute the tool.

        The text is measured before it is parsed. Text over ``MAX_PROPOSAL_TEXT_CHARS`` is a
        ``proposal_too_large`` deny, and text that is not a string or does not parse is a
        ``malformed_proposal`` deny. Either way the ledger keeps only its size and digest, and
        the reason carries no value or key name.
        """
        agent_id, hosting = getattr(agent, "agent_id", None), getattr(agent, "hosting", None)
        self._origin = "library"
        record = None
        if agent_id or hosting:
            record = {"id": agent_id, "hosting": hosting or "unspecified", "trusted": False}
        try:
            if isinstance(proposal_text, str) and len(proposal_text) > MAX_PROPOSAL_TEXT_CHARS:
                return self._deny("proposal_too_large", record, None, None,
                                  size_record(proposal_text, "proposal_text"))
            try:
                action, arguments, proposal = parse_proposal(proposal_text)
            except AgentConfigError:          # the message may quote a key name: not in the reason
                return self._deny("malformed_proposal", record, None, None,
                                  {**size_record(proposal_text, "proposal_text"),
                                   "proposal_text_type": type(proposal_text).__name__})
        except Exception as e:  # fail closed, as in authorize()
            return self._deny(f"internal_error:{type(e).__name__}", record, None, None)
        return self.authorize(action, arguments, proposal, agent_id=agent_id,
                              hosting=hosting, agent_session=agent_session)

    def revoke(self, reason: str) -> None:
        self.ledger.append("revocation", {"reason": reason})
        self.ledger.checkpoint()

    def _deny(self, reason: str, agent, path_a, path_b, extra: dict | None = None) -> Decision:
        try:
            self.ledger.append("decision", {"allowed": False, "reason": reason, "agent": agent,
                                            "origin": getattr(self, "_origin", "library"),
                                            **(extra or {}), **self._decision_context})
            self.ledger.checkpoint()
        except Exception as e:  # still a deny; say so, because the ledger now lacks this decision
            print(f"two-key: could not record deny decision {reason!r}: {type(e).__name__}: {e}"[:500],
                  file=sys.stderr)
            reason = f"ledger_failed:{e}" if isinstance(e, LedgerError) else f"ledger_failed:{type(e).__name__}"
        try:
            size = self.ledger.size()
        except Exception:
            size = 0
        return Decision(False, reason, None, path_a or {}, path_b or {}, size, agent)
