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


# verify() refuses a token whose lifetime (exp - iat) exceeds the verifier's max_ttl_seconds, or whose
# iat is more than MAX_CLOCK_SKEW_SECONDS in the future. TwoKey sets max_ttl_seconds to its own
# ttl_seconds, so a token can never be valid longer than the configured lifetime.
DEFAULT_MAX_TTL_SECONDS = 300
MAX_CLOCK_SKEW_SECONDS = 5.0


def _max_ttl(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("max_ttl_seconds must be a positive integer")
    return value


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

    def __init__(self, public_key, *, clock=None, max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS):
        self.public_key = public_key
        self.private_key = None
        self.clock = clock or time.time
        self.max_ttl_seconds = _max_ttl(max_ttl_seconds)

    def verify(self, token: Any) -> dict:
        """Check format, signature, lifetime, issue time, and expiry. Return the payload or raise TokenError."""
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
        try:
            issued_at, expires_at = float(payload["iat"]), float(payload["exp"])
        except (KeyError, TypeError, ValueError, OverflowError):  # a missing or non-numeric time field
            raise TokenError("malformed_token") from None
        if not (issued_at == issued_at and expires_at == expires_at) or expires_at <= issued_at:
            raise TokenError("malformed_token")  # NaN, or a token that expires before it is issued
        if expires_at - issued_at > self.max_ttl_seconds + 1e-3:  # 1 ms tolerance for float rounding
            raise TokenError("ttl_too_long")
        now = self.clock()
        if issued_at > now + MAX_CLOCK_SKEW_SECONDS:
            raise TokenError("issued_in_future")
        if now >= expires_at:
            raise TokenError("expired")
        return payload

    def issue(self, **kwargs) -> IssuedCapability:
        raise TokenError("verifier_cannot_mint")


class CapabilityIssuer(CapabilityVerifier):
    def __init__(self, private_key, public_key=None, *, clock=None, max_ttl_seconds: int = DEFAULT_MAX_TTL_SECONDS):
        super().__init__(public_key or private_key.public_key(), clock=clock, max_ttl_seconds=max_ttl_seconds)
        self.private_key = private_key

    def verifier(self) -> CapabilityVerifier:
        """A redeeming object. The private key is not on it."""
        return CapabilityVerifier(self.public_key, clock=self.clock, max_ttl_seconds=self.max_ttl_seconds)

    def issue(self, *, tool: str, arguments: dict, ledger_root: str, ledger_size: int,
              bytecode_hash: str, nl_hash: str, ttl_seconds: int = 120,
              spec_hash: str = "", form: dict | None = None,
              claimed_data_class: str | None = None) -> IssuedCapability:
        if self.private_key is None:
            raise TokenError("verifier_cannot_mint")
        if not isinstance(ttl_seconds, int) or ttl_seconds < 1:
            raise ValueError("ttl_seconds must be a positive integer")
        if ttl_seconds > self.max_ttl_seconds:
            raise ValueError(f"ttl_seconds exceeds this issuer's max_ttl_seconds ({self.max_ttl_seconds})")
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
