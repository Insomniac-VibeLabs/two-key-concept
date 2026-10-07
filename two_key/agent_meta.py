"""Bounds on operator/library-supplied agent identity metadata written to the ledger.

``authorize(..., agent_id=, hosting=)`` and ``authorize_from_agent`` accept free-form
strings from the caller (the operator/library, not a verified agent claim). An agent
process can still pass huge or non-string values into those kwargs; these checks refuse
them before they reach the ledger. ``None`` means omitted.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

MAX_AGENT_METADATA_CHARS = 256

REASON_INVALID = "invalid_agent_metadata"
REASON_TOO_LARGE = "agent_metadata_too_large"
REASON_LEDGER_BODY = "ledger_body_too_large"

# Fields copied from library agent_meta / AgentProposal.to_record() onto the ledger.
AGENT_META_FIELDS = ("agent_id", "provider", "hosting", "model")


class AgentMetadataError(ValueError):
    """Caller-supplied agent identity metadata failed the type or size check."""

    def __init__(self, reason: str, detail: dict):
        super().__init__(reason)
        self.reason = reason
        self.detail = detail


def _digest(text: str) -> str:
    return "sha256:" + hashlib.sha256(text.encode("utf-8", "surrogatepass")).hexdigest()


def check_agent_meta_field(field: str, value: Any) -> str | None:
    """Normalize one optional identity field for the ledger.

    ``None`` means omitted. A non-``str`` is ``invalid_agent_metadata`` (ledger the
    field name and type only). After strip, longer than ``MAX_AGENT_METADATA_CHARS``
    is ``agent_metadata_too_large`` (ledger ``field``, ``size``, ``digest`` — never
    the value, and never truncate). Returns the stripped string, or ``None`` when
    omitted or blank after strip.
    """
    if value is None:
        return None
    if type(value) is not str:
        raise AgentMetadataError(
            REASON_INVALID,
            {"field": field, "got": type(value).__name__},
        )
    stripped = value.strip()
    if len(stripped) > MAX_AGENT_METADATA_CHARS:
        raise AgentMetadataError(
            REASON_TOO_LARGE,
            {"field": field, "size": len(stripped), "digest": _digest(stripped)},
        )
    return stripped or None


def check_agent_meta_mapping(meta: Any, fields: tuple[str, ...] = AGENT_META_FIELDS) -> dict | None:
    """Validate free-form ``agent_meta`` values for the ledger. ``None``/empty → omitted."""
    if meta is None:
        return None
    if not isinstance(meta, Mapping):
        raise AgentMetadataError(
            REASON_INVALID,
            {"field": "agent_meta", "got": type(meta).__name__},
        )
    out: dict[str, str] = {}
    for key in fields:
        if key not in meta:
            continue
        normalized = check_agent_meta_field(key, meta.get(key))
        if normalized is not None:
            out[key] = normalized
    return out or None


def concept_agent_record(agent_id: Any = None, hosting: Any = None) -> dict | None:
    """Build the concept ledger ``agent`` dict, or ``None`` when both fields are omitted."""
    aid = check_agent_meta_field("agent_id", agent_id)
    host = check_agent_meta_field("hosting", hosting)
    if aid or host:
        return {"id": aid, "hosting": host or "unspecified", "trusted": False}
    return None
