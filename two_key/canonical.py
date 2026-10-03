"""Canonical encoding for the concept ledger, tokens, and judge bindings.

JSON with sorted keys and no insignificant whitespace. Non-finite numbers
are rejected so two encoders cannot disagree on NaN.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


class EncodingError(ValueError):
    pass


def _check(value: Any) -> None:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return
    if isinstance(value, int):
        return
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            raise EncodingError("non-finite number")
        return
    if isinstance(value, (list, tuple)):
        for item in value:
            _check(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise EncodingError("canonical object keys must be strings")
            _check(item)
        return
    raise EncodingError(f"unsupported type {type(value).__name__}")


def canonical_bytes(value: Any) -> bytes:
    _check(value)
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: Any) -> str:
    return digest_hex(canonical_bytes(value))
