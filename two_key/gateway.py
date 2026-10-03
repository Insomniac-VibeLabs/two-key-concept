"""Redeem a capability token. No scanning, antivirus, or DLP hooks.

The tool runs before the token is consumed. A tool exception leaves the token
redeemable. A process crash after a successful tool return and before the
redemption entry is written can allow a second run; the in-process and file
locks close the concurrent window only.
"""

from __future__ import annotations

import fcntl
import os
import threading
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
        self._locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()

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
        fn = self.tools.get(tool)
        if fn is None:
            return GatewayResult(False, "tool_not_registered")
        with self._hold(payload["jti"]):
            if self.ledger.is_redeemed(payload["jti"]):
                return GatewayResult(False, "already_redeemed")
            try:
                output = fn(arguments)
            except Exception as e:
                return GatewayResult(False, f"tool_error:{type(e).__name__}", None)
            try:
                self.ledger.append("redemption", {"jti": payload["jti"], "tool": tool})
                self.ledger.checkpoint()
            except LedgerError as e:
                return GatewayResult(False, f"ledger_failed:{e}", output)
        return GatewayResult(True, "redeemed", output)

    def _hold(self, jti: str):
        gateway = self
        class _Hold:
            def __enter__(self):
                with gateway._locks_guard:
                    self.lock = gateway._locks.setdefault(jti, threading.Lock())
                self.lock.acquire()
                path = gateway.ledger.path / f".redeem-{jti}.lock"
                self.fd = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
                fcntl.flock(self.fd, fcntl.LOCK_EX)
                return self
            def __exit__(self, *exc):
                fcntl.flock(self.fd, fcntl.LOCK_UN)
                os.close(self.fd)
                self.lock.release()
        return _Hold()
