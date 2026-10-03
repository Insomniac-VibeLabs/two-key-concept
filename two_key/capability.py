"""Single-use capability tokens bound to the ledger root at issuance.

Tokens are signed by a capability key that lives outside the ledger
directory. ``CapabilityVerifier`` holds only the public half. The gateway
uses that. ``CapabilityIssuer`` holds the private half and is what
``TwoKey`` uses to mint. The principal key signs the constitution and the
ledger head. It is not the minting key.
"""

from __future__ import annotations

import base64
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from .canonical import canonical_bytes, canonical_hash
from .keys import generate_private_key, load_private_key, public_key, save_private_key, save_public_key, sign, verify


class TokenError(ValueError):
    pass


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_dec(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def args_hash(arguments: dict) -> str:
    return canonical_hash(arguments)


def open_capability_key(ledger):
    """Load or create the minting key outside the ledger directory.

    The gateway must not call this. It verifies with the public half only.
    """
    path = ledger.capability_key_path()
    if path.exists():
        return load_private_key(path)
    key = generate_private_key()
    save_private_key(path, key)
    save_public_key(path.with_name("capability.pub.pem"), public_key(key))
    return key


@dataclass(frozen=True)
class IssuedCapability:
    token: str
    payload: dict

    @property
    def token_hash(self) -> str:
        return canonical_hash(self.token)


class CapabilityVerifier:
    """Checks a token. It cannot mint."""

    def __init__(self, public_key, *, clock=None):
        self.public_key = public_key
        self.private_key = None
        self.clock = clock or time.time

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

    def issue(self, **kwargs) -> IssuedCapability:
        raise TokenError("verifier_cannot_mint")


class CapabilityIssuer(CapabilityVerifier):
    def __init__(self, private_key, public_key=None, *, clock=None):
        super().__init__(public_key or private_key.public_key(), clock=clock)
        self.private_key = private_key

    def verifier(self) -> CapabilityVerifier:
        """A redeeming object. The private key is not on it."""
        return CapabilityVerifier(self.public_key, clock=self.clock)

    def issue(self, *, tool: str, arguments: dict, ledger_root: str, ledger_size: int,
              bytecode_hash: str, nl_hash: str, ttl_seconds: int = 120,
              spec_hash: str = "", form: dict | None = None,
              claimed_data_class: str | None = None) -> IssuedCapability:
        if self.private_key is None:
            raise TokenError("verifier_cannot_mint")
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
