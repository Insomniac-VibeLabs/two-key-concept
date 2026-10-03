"""Redeem a capability token. No scanning, antivirus, or DLP hooks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .capability import TokenError, args_hash
from .ledger import LedgerError


@dataclass(frozen=True)
class GatewayResult:
    allowed: bool
    reason: str
    output: Any = None


class ToolGateway:
    def __init__(self, ledger, issuer, compiled, *, tools: dict[str, Callable] | None = None):
        self.ledger = ledger
        self.issuer = issuer
        self.compiled = compiled
        self.tools = tools or {}

    def invoke(self, token: str, tool: str, arguments: dict) -> GatewayResult:
        try:
            payload = self.issuer.verify(token)
        except TokenError as e:
            return GatewayResult(False, str(e))
        if payload["tool"] != tool:
            return GatewayResult(False, "tool_mismatch")
        if payload["args_hash"] != args_hash(arguments):
            return GatewayResult(False, "args_mismatch")
        if payload["bytecode_hash"] != self.compiled.bytecode_hash or payload["nl_hash"] != self.compiled.nl_hash:
            return GatewayResult(False, "constitution_mismatch")
        size = payload["ledger_size"]
        if not isinstance(size, int) or size < 0 or size > self.ledger.size():
            return GatewayResult(False, "ledger_size_invalid")
        if self.ledger.merkle_root(size) != payload["ledger_root"]:
            return GatewayResult(False, "ledger_root_mismatch")
        if self.ledger.kinds_after(size, {"constitution_loaded", "revocation"}):
            return GatewayResult(False, "revoked_or_reloaded")
        if self.ledger.is_redeemed(payload["jti"]):
            return GatewayResult(False, "already_redeemed")
        fn = self.tools.get(tool)
        if fn is None:
            return GatewayResult(False, "tool_not_registered")
        try:
            self.ledger.append("redemption", {"jti": payload["jti"], "tool": tool})
            self.ledger.checkpoint()
        except LedgerError as e:
            return GatewayResult(False, f"ledger_failed:{e}")
        try:
            output = fn(arguments)
        except Exception as e:  # tool failure is not an authorization failure
            return GatewayResult(True, f"tool_error:{type(e).__name__}", None)
        return GatewayResult(True, "redeemed", output)
