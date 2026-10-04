"""Redeem a capability token. No scanning, antivirus, or DLP hooks.

The gateway keeps a ``CapabilityVerifier``. It does not keep the minting
key. It refuses a verifier whose key is the principal key, and it redeems a
token only if the verifier's key fingerprint is the one pinned in the
ledger's ``constitution_loaded`` entry (``capability_key_mismatch``). A redemption intent is checkpointed before the tool runs. A later
retry of that intent does not run the tool. A tool exception appends an
abort and leaves the token usable. A crash after a successful return
cannot run the token again, because the intent is already on the ledger.
"""

from __future__ import annotations

import os
import threading
from dataclasses import dataclass
from typing import Any, Callable

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX only
    fcntl = None

from .capability import (DEFAULT_MAX_TTL_SECONDS, CapabilityIssuer, CapabilityVerifier, TokenError, _raw,
                         args_hash, capability_key_fingerprint)
from .derive import DeriveError, args_too_large, blocked_from_rules, derive, dropped_keys, form_for, forms_match, project_arguments
from .ledger import LedgerError


_BOUND_FIELDS = ("jti", "tool", "args_hash", "bytecode_hash", "nl_hash", "ledger_root", "ledger_size")


@dataclass(frozen=True)
class GatewayResult:
    allowed: bool
    reason: str
    output: Any = None


def _as_verifier(issuer) -> CapabilityVerifier:
    """The redeeming object keeps the public key only."""
    if isinstance(issuer, CapabilityIssuer):
        return issuer.verifier()
    if isinstance(issuer, CapabilityVerifier):
        return CapabilityVerifier(issuer.public_key, clock=issuer.clock, max_ttl_seconds=issuer.max_ttl_seconds)
    public = getattr(issuer, "public_key", None)
    if public is None or not hasattr(issuer, "verify"):
        raise TokenError("gateway requires a token verifier")
    return CapabilityVerifier(public, clock=getattr(issuer, "clock", None),
                              max_ttl_seconds=getattr(issuer, "max_ttl_seconds", DEFAULT_MAX_TTL_SECONDS))


class ToolGateway:
    def __init__(self, ledger, issuer, compiled, *, tools: dict[str, Callable] | None = None):
        self.ledger = ledger
        self.issuer = _as_verifier(issuer)
        principal = getattr(ledger, "public_key", None)
        if principal is not None and _raw(self.issuer.public_key) == _raw(principal):
            raise TokenError("capability_key_is_principal_key")
        self._fingerprint = capability_key_fingerprint(self.issuer.public_key)
        self.compiled = compiled
        self.tools = tools or {}
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

    def invoke(self, token: str, tool: str, arguments: dict) -> GatewayResult:
        try:
            payload = self.issuer.verify(token)
        except TokenError as e:
            return GatewayResult(False, str(e))
        if any(name not in payload for name in _BOUND_FIELDS):
            return GatewayResult(False, "malformed_token")  # a signed token without a binding field
        if args_too_large(arguments):
            return GatewayResult(False, "args_too_large")  # before hashing, deriving, or ledgering
        if payload["tool"] != tool:
            return GatewayResult(False, "tool_mismatch")
        if payload["args_hash"] != args_hash(arguments):
            return GatewayResult(False, "args_mismatch")
        if payload["bytecode_hash"] != self.compiled.bytecode_hash or payload["nl_hash"] != self.compiled.nl_hash:
            return GatewayResult(False, "constitution_mismatch")
        if payload.get("spec_hash", "") != self.compiled.spec_hash:
            return GatewayResult(False, "constitution_mismatch")
        if not self.compiled.specs_enforced:
            return GatewayResult(False, "tool_specs_required")
        spec = self.compiled.tool_specs.get(tool)
        if spec is None:
            return GatewayResult(False, "tool_specs_required")
        if "form" not in payload or "claimed_data_class" not in payload:
            return GatewayResult(False, "derived_mismatch")
        try:
            derived = derive(spec, arguments)
            fresh = form_for(derived, payload["claimed_data_class"],
                             blocked_from_rules(self.compiled.rules))
        except DeriveError:
            return GatewayResult(False, "derived_mismatch")
        if not forms_match(payload["form"], fresh):
            return GatewayResult(False, "derived_mismatch")
        size = payload["ledger_size"]
        if not isinstance(size, int) or size < 0 or size > self.ledger.size():
            return GatewayResult(False, "ledger_size_invalid")
        if self.ledger.merkle_root(size) != payload["ledger_root"]:
            return GatewayResult(False, "ledger_root_mismatch")
        if self._pinned_at(size) != self._fingerprint:
            return GatewayResult(False, "capability_key_mismatch")
        if self.ledger.kinds_after(size, {"constitution_loaded", "revocation"}):
            return GatewayResult(False, "revoked_or_reloaded")
        fn = self.tools.get(tool)
        if fn is None:
            return GatewayResult(False, "tool_not_registered")
        with self._hold(payload["jti"]):
            if self.ledger.is_redeemed(payload["jti"]):
                return GatewayResult(False, "already_redeemed")
            if self.ledger.redemption_started(payload["jti"]):
                return GatewayResult(False, "already_attempted")
            try:
                self.ledger.append("redemption_started", {"jti": payload["jti"], "tool": tool,
                                                          "dropped_keys": dropped_keys(spec, arguments)})
                self.ledger.checkpoint()
            except LedgerError as e:
                return GatewayResult(False, f"ledger_failed:{e}")
            try:
                output = fn(project_arguments(spec, arguments))
            except Exception as e:
                try:
                    self.ledger.append("redemption_aborted", {"jti": payload["jti"], "tool": tool})
                    self.ledger.checkpoint()
                except LedgerError as le:
                    return GatewayResult(False, f"ledger_failed:{le}")
                return GatewayResult(False, f"tool_error:{type(e).__name__}", None)
            try:
                self.ledger.append("redemption", {"jti": payload["jti"], "tool": tool})
                self.ledger.checkpoint()
            except LedgerError as e:
                return GatewayResult(False, f"ledger_failed:{e}", output)
        return GatewayResult(True, "redeemed", output)

    def _pinned_at(self, size: int) -> str | None:
        """The capability key fingerprint in the last ``constitution_loaded`` entry before ``size``."""
        for entry in reversed(self.ledger.entries[:size]):
            if entry.kind == "constitution_loaded":
                return entry.body.get("capability_key_fingerprint")
        return None

    def _hold(self, jti: str):
        gateway = self
        class _Hold:
            def __enter__(self):
                with gateway._locks_guard:
                    self.lock = gateway._locks.setdefault(jti, threading.Lock())
                self.lock.acquire()
                self.fd = None
                if fcntl is None:
                    return self
                try:
                    path = gateway.ledger.redeem_lock_path(jti)
                    self.fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
                    fcntl.flock(self.fd, fcntl.LOCK_EX)
                    return self
                except BaseException:
                    if self.fd is not None:
                        os.close(self.fd)
                    self.lock.release()
                    raise

            def __exit__(self, *exc):
                if self.fd is not None:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                    os.close(self.fd)
                self.lock.release()
        return _Hold()
