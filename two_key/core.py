"""Two-Key concept: a tool call runs only if Path A and Path B both allow.

``authorize_from_agent`` always runs both paths and does not execute tools.
Hosting (local or cloud) is recorded and never treated as trust.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any

from .action import ActionValidationError, normalize_action
from .canonical import canonical_hash
from .agents import parse_proposal
from .capability import CapabilityIssuer
from .compiler import CompiledConstitution, compile_both
from .constitution import Constitution, verify_signed
from .ledger import LedgerError
from .policy_vm import PolicyVM
from .quorum import QuorumPolicy, convene


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
                 allow_test_doubles: bool = False, clock=None):
        if not allow_test_doubles and any(getattr(j, "is_test_double", False) for j in judges):
            raise ValueError("test-double judges refused; pass allow_test_doubles=True only for offline tests")
        self.ledger = ledger
        self.public_key = public_key
        self.private_key = private_key
        self.constitution = constitution
        self.compiled: CompiledConstitution = compile_both(constitution.prose, constitution.hard_rules)
        self.vm = PolicyVM(self.compiled.bytecode)
        self.judges = list(judges)
        self.quorum = quorum or QuorumPolicy(required_yes=min(2, max(1, len(judges))))
        self.ttl_seconds = ttl_seconds
        self.issuer = CapabilityIssuer(private_key, public_key, clock=clock) if private_key else None
        self._clock = clock
        self.ledger.append("constitution_loaded", {
            "digest": constitution.digest,
            "bytecode_hash": self.compiled.bytecode_hash,
            "nl_hash": self.compiled.nl_hash,
        })
        self.ledger.checkpoint()

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
        path_a = self.vm.eval(normalized)
        path_a_rec = {"allowed": path_a.allowed, "reason": path_a.reason, "denied_by": path_a.denied_by}
        binding = {
            "action_hash": canonical_hash(normalized.to_record()),
            "constitution_hash": self.constitution.digest,
            "nl_hash": self.compiled.nl_hash,
            "bytecode_hash": self.compiled.bytecode_hash,
        }
        # Both paths always answer. A Path A deny does not skip Path B.
        quorum = convene(self.judges, self.compiled.judge_text, normalized, proposal,
                         self.quorum, binding, arguments, agent_session)
        path_b_rec = {"passed": quorum.passed, "reason": quorum.reason,
                      "yes": quorum.yes, "no": quorum.no, "abstain": quorum.abstain}
        allowed = bool(path_a.allowed and quorum.passed)
        reason = "both_paths_allow" if allowed else (path_a.reason if not path_a.allowed else quorum.reason)
        token = None
        try:
            self.ledger.append("proposal", {"tool": normalized.tool, "proposal": proposal, "agent": agent})
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
