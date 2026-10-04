"""Canonical encoding for the concept ledger, tokens, and judge bindings.

JSON with sorted keys and no insignificant whitespace. Non-finite numbers
are rejected so two encoders cannot disagree on NaN. Containers nested more
than ``MAX_DEPTH`` levels are an ``EncodingError``. The walk is iterative, so
the limit does not depend on the Python version or on how deep the caller's
stack is.

Inputs (tool args, the action claim, a non-text proposal) are held to
``MAX_INPUT_DEPTH``, which is ``WRAP_DEPTH`` levels under ``MAX_DEPTH``. That
leaves room for the two levels an input gains when it is wrapped. A ledger
entry's hash covers ``{"body": {field: value}}``, and a judge's action record
carries the args as ``{"raw": {"tool_args": args}}``. So an input that is
accepted can always be encoded again inside its wrapper.
"""

from __future__ import annotations

import hashlib
import json
import math
from typing import Any


class EncodingError(ValueError):
    pass


# Containers (objects and arrays) nested more than this many levels are not encoded.
MAX_DEPTH = 64
# Levels an input gains when it is wrapped: a ledger body field, or raw.tool_args in a judge's record.
WRAP_DEPTH = 2
# The limit on tool args, the action claim, and a non-text proposal.
MAX_INPUT_DEPTH = MAX_DEPTH - WRAP_DEPTH


def nested_too_deeply(what: str = "value is") -> str:
    return f"{what} nested too deeply"


def _check(value: Any, max_depth: int, what: str) -> None:
    """Walk ``value`` without recursion. The outermost container is level 1."""
    stack = [(value, 1)]
    while stack:
        item, level = stack.pop()
        if isinstance(item, bool) or item is None or isinstance(item, (str, int)):
            continue
        if isinstance(item, float):
            if math.isnan(item) or math.isinf(item):
                raise EncodingError("non-finite number")
            continue
        if isinstance(item, (list, tuple, dict)):
            if level > max_depth:
                raise EncodingError(nested_too_deeply(what))
            if isinstance(item, dict):
                for key, child in item.items():
                    if not isinstance(key, str):
                        raise EncodingError("canonical object keys must be strings")
                    stack.append((child, level + 1))
            else:
                stack.extend((child, level + 1) for child in item)
            continue
        raise EncodingError(f"unsupported type {type(item).__name__}")


def canonical_bytes(value: Any, *, max_depth: int = MAX_DEPTH, what: str = "value is") -> bytes:
    """Canonical JSON of ``value``. ``EncodingError`` if it nests more than ``max_depth`` levels, holds a
    non-finite number, a non-string key, or a type JSON has no form for. ``what`` names the value in the
    nesting error (``"tool args are"`` gives ``tool args are nested too deeply``)."""
    try:
        _check(value, max_depth, what)
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except RecursionError:  # not expected under MAX_DEPTH; kept so a crash is never the answer
        raise EncodingError(nested_too_deeply(what)) from None


def digest_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_hash(value: Any) -> str:
    return digest_hex(canonical_bytes(value))
