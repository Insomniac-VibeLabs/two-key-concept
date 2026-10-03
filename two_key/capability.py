"""Single-use capability tokens bound to the ledger root at issuance."""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes, canonical_hash
from .keys import sign, verify


class TokenError(ValueError):
    pass


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_dec(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def args_hash(arguments: dict) -> str:
    return canonical_hash(arguments)


@dataclass(frozen=True)
class IssuedCapability:
    token: str
    payload: dict

    @property
    def token_hash(self) -> str:
        return canonical_hash(self.token)


class CapabilityIssuer:
    def __init__(self, private_key, public_key=None, *, clock=None):
        self.private_key = private_key
        self.public_key = public_key or private_key.public_key()
        self.clock = clock or time.time

    def issue(self, *, tool: str, arguments: dict, ledger_root: str, ledger_size: int,
              bytecode_hash: str, nl_hash: str, ttl_seconds: int = 120,
              spec_hash: str = "", form: dict | None = None,
              claimed_data_class: str | None = None) -> IssuedCapability:
        if not isinstance(ttl_seconds, int) or ttl_seconds < 1:
            raise ValueError("ttl_seconds must be a positive integer")
        now = int(self.clock())
        payload = {
            "v": 1,
            "jti": secrets.token_hex(16),
            "tool": tool,
            "args_hash": args_hash(arguments),
            "ledger_root": ledger_root,
            "ledger_size": ledger_size,
            "bytecode_hash": bytecode_hash,
            "nl_hash": nl_hash,
            "spec_hash": spec_hash,
            "iat": now,
            "exp": now + ttl_seconds,
        }
        if form is not None:
            payload["form"] = form
            payload["claimed_data_class"] = claimed_data_class
        body = _b64u(canonical_bytes(payload))
        signature = sign(self.private_key, body.encode("ascii"))
        return IssuedCapability(f"tk1.{body}.{signature}", payload)

    def verify(self, token: Any) -> dict:
        if not isinstance(token, str) or token.count(".") != 2 or not token.startswith("tk1."):
            raise TokenError("malformed_token")
        _, body, signature = token.split(".")
        if not verify(self.public_key, body.encode("ascii"), signature):
            raise TokenError("bad_signature")
        try:
            payload = json.loads(_b64u_dec(body))
        except ValueError:
            raise TokenError("malformed_token") from None
        if not isinstance(payload, dict) or payload.get("v") != 1:
            raise TokenError("malformed_token")
        if self.clock() >= float(payload["exp"]):
            raise TokenError("expired")
        return payload
