"""Redeem a capability token. No scanning, antivirus, or DLP hooks.

The gateway keeps a ``CapabilityVerifier``. It does not keep the minting
key. It refuses a verifier whose key is the principal key, and it redeems a
token only if the verifier's key fingerprint is the one pinned in the
ledger's ``constitution_loaded`` entry (``capability_key_mismatch``). A redemption intent is checkpointed before the tool runs. A later
retry of that intent does not run the tool. A tool exception appends an
abort and leaves the token usable. A crash after a successful return
cannot run the token again, because the intent is already on the ledger.
A refusal of an authenticated token is ledgered as ``gateway_denied`` (reason,
jti, tool, argument size and digest); a token that does not verify writes nothing.
"""

from __future__ import annotations

import os
import sys
import threading
from dataclasses import dataclass
from typing import Any, Callable

try:
    import fcntl
except ImportError:  # pragma: no cover - POSIX only
    fcntl = None

from .capability import (DEFAULT_MAX_TTL_SECONDS, CapabilityIssuer, CapabilityVerifier, TokenError, _raw,
                         capability_key_fingerprint)
from .agent_meta import type_tag
from .action import MAX_TOOL_NAME_CHARS, TOOL_NAME
from .canonical import MAX_INPUT_DEPTH, EncodingError, OversizeError, canonical_bytes, digest_hex, to_plain
from .derive import (MAX_ARGS_BYTES, DeriveError, blocked_from_rules, canonical_too_large, derive, dropped_keys, form_for, forms_match,
                     project_arguments, size_record)
from .ledger import LedgerError


_MAX_REASON_CHARS = 200
_MAX_JTI_CHARS = 64


def _short(value) -> str | None:
    """A jti for the ledger: a short string, else nothing (the token is signed, but keep entries small)."""
    return value if isinstance(value, str) and len(value) <= _MAX_JTI_CHARS else None


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
        """Redeem ``token`` for ``tool(arguments)``.

        A token that does not verify (bad signature, expired, malformed) is refused without a
        ledger entry, so an unauthenticated caller cannot write to the ledger. Any later refusal of
        an authenticated token is ledgered as ``gateway_denied`` with the reason, the jti, the tool
        name (only if it is a short identifier), and the size and digest of the arguments, never
        their values.
        """
        try:
            payload = self.issuer.verify(token)
        except TokenError as e:
            return GatewayResult(False, str(e))
        result, encoded = self._invoke_verified(payload, tool, arguments)
        if result.allowed or result.reason.startswith(("ledger_failed:", "tool_error:")):
            return result      # a tool error is already ledgered (redemption_aborted); a ledger failure cannot be
        return self._record_deny(result, payload, tool, encoded)

    def _record_deny(self, result: GatewayResult, payload: dict, tool, encoded: dict) -> GatewayResult:
        body = {"reason": result.reason[:_MAX_REASON_CHARS], "jti": _short(payload.get("jti"))}
        if isinstance(tool, str) and len(tool) <= MAX_TOOL_NAME_CHARS and TOOL_NAME.fullmatch(tool):
            body["tool"] = tool
        else:
            body.update({"tool": None, **size_record(tool, "tool")})
        frozen = encoded.get("frozen")
        if frozen is not None:
            body.update({"tool_args_size": len(frozen), "tool_args_digest": "sha256:" + digest_hex(frozen),
                         "tool_args_omitted": True})
        elif "plain" in encoded:     # copied, but not encodable (NaN, for example): measured from the copy
            body.update(size_record(encoded["plain"], "tool_args"))
        else:                        # not copied (too deep, too many items, an unsupported type): not measured
            body.update({"tool_args_size": -1, "tool_args_digest": None, "tool_args_omitted": True})
        try:
            self.ledger.append_bounded("gateway_denied", body)
            self.ledger.checkpoint()
        except Exception as e:  # still a deny; say so, because the ledger now lacks it
            print(f"two-key: could not record gateway deny {result.reason[:_MAX_REASON_CHARS]!r}: "
                  f"{type_tag(e)}"[:500], file=sys.stderr)
            reason = f"ledger_failed:{e}" if isinstance(e, LedgerError) else f"ledger_failed:{type_tag(e)}"
            return GatewayResult(False, reason, result.output)
        return result

    def _invoke_verified(self, payload: dict, tool: str, arguments: dict) -> tuple[GatewayResult, dict]:
        """Run the checks and the tool; also return the plain copy and encoded bytes, as far as they got."""
        encoded: dict = {}
        result = self._redeem(payload, tool, arguments, encoded)
        return result, encoded

    def _redeem(self, payload: dict, tool: str, arguments: dict, encoded: dict) -> GatewayResult:
        if any(name not in payload for name in _BOUND_FIELDS):
            return GatewayResult(False, "malformed_token")  # a signed token without a binding field
        # Copied once into built-in types (any Mapping becomes a dict); every check, the hash, and the
        # tool read the copy. Encoded before the size check, so nesting too deep is invalid_call on every
        # Python version. Encoded once: the same bytes give the hash and settle the size cap.
        try:
            arguments = to_plain(arguments, max_depth=MAX_INPUT_DEPTH, what="tool args are",
                                 max_items=MAX_ARGS_BYTES // 2)
        except OversizeError:
            return GatewayResult(False, "args_too_large")
        except EncodingError as e:
            return GatewayResult(False, f"invalid_call:{e}")
        encoded["plain"] = arguments
        try:
            frozen = canonical_bytes(arguments, max_depth=MAX_INPUT_DEPTH, what="tool args are")
        except EncodingError as e:   # nested too deeply, NaN, or a non-string key; the same reason as authorize
            return GatewayResult(False, f"invalid_call:{e}")
        encoded["frozen"] = frozen
        hashed = digest_hex(frozen)
        if canonical_too_large(frozen, arguments):
            return GatewayResult(False, "args_too_large")  # before deriving or ledgering
        if payload["tool"] != tool:
            return GatewayResult(False, "tool_mismatch")
        if payload["args_hash"] != hashed:
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
                self.ledger.append_bounded("redemption_started", {"jti": payload["jti"], "tool": tool,
                                                                  "dropped_keys": dropped_keys(spec, arguments)})
                self.ledger.checkpoint()
            except LedgerError as e:
                return GatewayResult(False, f"ledger_failed:{e}")
            try:
                output = fn(project_arguments(spec, arguments))
            except Exception as e:
                try:
                    self.ledger.append_bounded("redemption_aborted", {"jti": payload["jti"], "tool": tool})
                    self.ledger.checkpoint()
                except LedgerError as le:
                    return GatewayResult(False, f"ledger_failed:{le}")
                return GatewayResult(False, f"tool_error:{type_tag(e)}", None)
            try:
                self.ledger.append_bounded("redemption", {"jti": payload["jti"], "tool": tool})
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
