"""Two-Key concept: a tool call runs only if Path A and Path B both allow.

``authorize_from_agent`` always runs both paths and does not execute tools.
Hosting (local or cloud) is recorded and never treated as trust.

``TwoKey`` refuses to start (``TwoKeyConfigError``) with no judge, with no
Path B deadline, with duplicate judge ids, without an operator declaration
of the monitored agent (``monitored_agent_required:``), or when a judge
could be that agent (``judge_matches_agent:``; see identity.py).
"""

from __future__ import annotations

from dataclasses import dataclass, asdict, replace
from typing import Any, Mapping

from .action import Action, ActionValidationError, normalize_action
from .canonical import canonical_hash
from .agents import parse_proposal
from .capability import CapabilityIssuer, open_capability_key
from .compiler import CompiledConstitution, compile_both
from .constitution import Constitution, ConstitutionError, verify_signed
from .identity import (AgentDeclaration, IdentityError, SeparationReport, check_separation,
                       configured_agent_identity, judge_identity)
from .derive import DeriveError, blocked_from_rules, derive, disagreement, disallowed_party, form_for
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

    def to_record(self) -> dict:
        return asdict(self)


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
        self.quorum = quorum or QuorumPolicy(required_yes=min(2, len(self.judges)))
        if self.quorum.timeout_seconds is None:
            # Fail closed on a hung judge: every round ends by the deadline, and a late judge abstains.
            raise TwoKeyConfigError("Path B needs a hard deadline: quorum timeout_seconds must be a positive "
                                    "number, not None")
        check_judge_set(self.judges, self.quorum)
        # Judge != monitored agent, from operator configuration only (identity.py).
        self.separation = self._check_separation(monitored_agent, allow_test_doubles)
        self.ttl_seconds = ttl_seconds
        # The minting key is not the principal key, and it is not given to the gateway.
        self.issuer = CapabilityIssuer(open_capability_key(ledger), clock=clock) if private_key else None
        self._clock = clock
        self.ledger.append("constitution_loaded", {
            "digest": constitution.digest,
            "bytecode_hash": self.compiled.bytecode_hash,
            "nl_hash": self.compiled.nl_hash,
            "spec_hash": self.compiled.spec_hash,
            "judge_agent_separation": self.separation.to_record(),
        })
        self.ledger.checkpoint()

    def _check_separation(self, monitored_agent: Any, allow_test_doubles: bool) -> SeparationReport:
        """Refuse to start if any judge could be the monitored agent. See identity.py."""
        if monitored_agent is None:
            raise TwoKeyConfigError("monitored_agent_required: declare the monitored agent (monitored_agent= "
                                    "with model, provider, base_url, and credential_env or credential: none) "
                                    "whenever judges are configured")
        decls = monitored_agent if isinstance(monitored_agent, (list, tuple)) else [monitored_agent]
        try:
            agents = []
            for d in decls:
                if isinstance(d, AgentDeclaration) or isinstance(d, Mapping):
                    if not isinstance(d, AgentDeclaration):
                        d = AgentDeclaration.from_mapping(d)
                    agents.append(d.resolve(allow_in_process=allow_test_doubles))
                elif all(hasattr(d, k) for k in ("agent_id", "model", "base_url", "credential")):
                    agents.append(configured_agent_identity(d))  # a MonitoredAgent from agents.yaml
                else:
                    raise IdentityError("monitored_agent must be a mapping, an AgentDeclaration, or a MonitoredAgent")
            judges = [judge_identity(j) for j in self.judges]
            return check_separation(agents, judges, self.quorum.allow_same_provider_judge)
        except IdentityError as e:
            raise TwoKeyConfigError(str(e)) from e

    @classmethod
    def load(cls, ledger, public_key, envelope: dict, judges: list, **kw) -> "TwoKey":
        return cls(ledger, public_key, verify_signed(envelope, public_key), judges, **kw)

    def authorize(self, action: dict, arguments: dict, proposal: str, *,
                  agent_id: str | None = None, hosting: str | None = None,
                  agent_session: str | None = None) -> Decision:
        agent = None
        if agent_id or hosting:
            # Hosting is a deployment fact, not a trust decision.
            agent = {"id": agent_id, "hosting": hosting or "unspecified", "trusted": False}
        try:
            normalized = normalize_action(action)
        except ActionValidationError as e:
            return self._deny(f"malformed_action:{e}", agent, None, None)
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
        # Both paths always answer. A Path A deny does not skip Path B.
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
                })
            self.ledger.append("path_a", path_a_rec)
            self.ledger.append("path_b", path_b_rec)
            if allowed:
                if self.issuer is None:
                    allowed, reason = False, "no_issuer_key"
                else:
                    issued = self.issuer.issue(
                        tool=normalized.tool, arguments=arguments,
                        ledger_root=self.ledger.merkle_root(), ledger_size=self.ledger.size(),
                        bytecode_hash=self.compiled.bytecode_hash, nl_hash=self.compiled.nl_hash,
                        spec_hash=self.compiled.spec_hash,
                        form=form, claimed_data_class=claimed_data_class if form is not None else None,
                        ttl_seconds=self.ttl_seconds)
                    token = issued.token
                    self.ledger.append("capability_issued", {"jti": issued.payload["jti"],
                                                            "token_hash": issued.token_hash,
                                                            "ledger_root": issued.payload["ledger_root"]})
            self.ledger.append("decision", {"allowed": allowed, "reason": reason, "agent": agent})
            self.ledger.checkpoint()
        except LedgerError as e:
            return Decision(False, f"ledger_failed:{e}", None, path_a_rec, path_b_rec, self.ledger.size(), agent)
        return Decision(allowed, reason, token if allowed else None, path_a_rec, path_b_rec, self.ledger.size(), agent)

    def authorize_from_agent(self, agent, proposal_text: str, *, agent_session: str | None = None) -> Decision:
        """Parse an untrusted agent proposal, run both paths, and do not execute the tool."""
        action, arguments, proposal = parse_proposal(proposal_text)
        return self.authorize(action, arguments, proposal, agent_id=getattr(agent, "agent_id", None),
                              hosting=getattr(agent, "hosting", None), agent_session=agent_session)

    def revoke(self, reason: str) -> None:
        self.ledger.append("revocation", {"reason": reason})
        self.ledger.checkpoint()

    def _deny(self, reason: str, agent, path_a, path_b) -> Decision:
        try:
            self.ledger.append("decision", {"allowed": False, "reason": reason, "agent": agent})
            self.ledger.checkpoint()
        except LedgerError as e:
            reason = f"ledger_failed:{e}"
        return Decision(False, reason, None, path_a or {}, path_b or {}, self.ledger.size(), agent)
