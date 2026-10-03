"""Derive Path A's form from the argument bytes and a signed tool spec.

The agent may still send amount, data class, counterparty, and irreversible.
Those are claims. When the signed constitution has a spec for the tool, the
values Path A sees come from the spec and the arguments. A claim that
disagrees is a deny. This module does not read English and it does not
classify free text.

Keys the spec does not name do not reach the tool. ``deny_unmapped`` defaults
off: those keys are dropped at the gateway. When a spec sets it, an unnamed
key is a deny instead. A declared path covers that value and everything
under it. A counterparty path copies only values on its allow list, and the
tool receives the canonical value. A payload path is not interpreted.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass
from typing import Any, Mapping

from .action import DATA_CLASSES, MAX_AMOUNT_USD


class DeriveError(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


_SEGMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


@dataclass(frozen=True)
class Derived:
    amount_usd: float | None
    counterparties: tuple[str, ...]
    irreversible: bool
    data_class_floor: str


def _cents(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DeriveError("amount_unreadable")
    number = float(value)
    if math.isnan(number) or math.isinf(number) or number < 0:
        raise DeriveError("amount_unreadable")
    cents = round(number * 100)
    if abs(number * 100 - cents) > 1e-6:
        raise DeriveError("amount_unreadable")
    return int(cents)


def lookup(document: Mapping[str, Any], path: str) -> tuple[bool, Any]:
    current: Any = document
    for part in path.split("."):
        if not isinstance(current, Mapping) or part not in current:
            return False, None
        current = current[part]
    return True, current


def _parties_at(raw: Any) -> list[str]:
    if isinstance(raw, str):
        values = [raw]
    elif isinstance(raw, list) and raw and all(isinstance(item, str) for item in raw):
        values = list(raw)
    else:
        raise DeriveError("counterparty_unreadable")
    parties: list[str] = []
    for value in values:
        party = value.strip().casefold()
        if not party:
            raise DeriveError("counterparty_missing")
        parties.append(party)
    return parties


def _clone(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {key: _clone(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_clone(item) for item in value]
    return value


def _assign(dest: dict, path: str, value: Any) -> None:
    parts = path.split(".")
    current = dest
    for part in parts[:-1]:
        nxt = current.get(part)
        if not isinstance(nxt, dict):
            nxt = {}
            current[part] = nxt
        current = nxt
    current[parts[-1]] = value


def disallowed_party(spec: Mapping[str, Any], arguments: Mapping[str, Any]) -> bool:
    """True when a copied party is not on that path's allow list."""
    for entry in spec.get("counterparties") or []:
        if not isinstance(entry, Mapping):
            continue
        found, raw = lookup(arguments, entry["json_path"])
        if not found:
            continue
        allow = set(entry.get("allow") or [])
        if any(party not in allow for party in _parties_at(raw)):
            return True
    return False


def project_arguments(spec: Mapping[str, Any], arguments: Mapping[str, Any]) -> dict:
    """Arguments the tool may see.

    Unnamed keys are dropped. A counterparty path is the canonical party
    Path A checked, not the raw spelling. A payload path is copied whole,
    including its children, and is not interpreted.
    """
    if not isinstance(arguments, Mapping):
        return {}
    out: dict[str, Any] = {}
    for entry in spec.get("payload") or []:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("json_path"), str):
            continue
        found, raw = lookup(arguments, entry["json_path"])
        if found:
            _assign(out, entry["json_path"], _clone(raw))
    amount = spec.get("amount")
    if isinstance(amount, Mapping):
        path = amount.get("json_path")
        if isinstance(path, str):
            found, raw = lookup(arguments, path)
            if found:
                _assign(out, path, _clone(raw))
        currency_path = amount.get("currency_path")
        if isinstance(currency_path, str):
            found, raw = lookup(arguments, currency_path)
            if found:
                _assign(out, currency_path, raw.strip().casefold() if isinstance(raw, str) else _clone(raw))
    for entry in spec.get("counterparties") or []:
        if not isinstance(entry, Mapping) or not isinstance(entry.get("json_path"), str):
            continue
        path = entry["json_path"]
        found, raw = lookup(arguments, path)
        if not found:
            continue
        parties = _parties_at(raw)
        if isinstance(raw, str):
            _assign(out, path, parties[0])
        else:
            _assign(out, path, list(dict.fromkeys(parties)))
    return out


def _declared_paths(spec: Mapping[str, Any]) -> tuple[str, ...]:
    paths: list[str] = []
    amount = spec.get("amount")
    if isinstance(amount, Mapping):
        for key in ("json_path", "currency_path"):
            value = amount.get(key)
            if isinstance(value, str):
                paths.append(value)
    for key in ("counterparties", "payload"):
        for entry in spec.get(key) or []:
            if isinstance(entry, Mapping) and isinstance(entry.get("json_path"), str):
                paths.append(entry["json_path"])
    return tuple(paths)


def _unmapped(arguments: Mapping[str, Any], declared: tuple[str, ...]) -> bool:
    """True when an argument key is outside every declared path.

    A declared path covers itself and its children. Ancestors of a declared
    path are walked. Lists and scalars are not walked, so a named value does
    not require a key list for every nested level.
    """
    declared_set = set(declared)

    def is_prefix(path: str) -> bool:
        needle = path + "."
        return any(item.startswith(needle) for item in declared_set)

    def walk(node: Mapping[str, Any], prefix: str) -> bool:
        for key, value in node.items():
            if not isinstance(key, str) or not _SEGMENT.fullmatch(key):
                return True
            path = f"{prefix}.{key}" if prefix else key
            if path in declared_set:
                continue
            if is_prefix(path):
                if isinstance(value, Mapping) and walk(value, path):
                    return True
                continue
            return True
        return False

    return walk(arguments, "")


def derive(spec: Mapping[str, Any], arguments: Mapping[str, Any]) -> Derived:
    """Read amount and counterparties from ``arguments`` using ``spec`` paths."""
    if not isinstance(arguments, Mapping):
        raise DeriveError("arguments_not_object")
    amount_spec = spec.get("amount")
    amount: float | None = None
    if amount_spec:
        found, raw = lookup(arguments, amount_spec["json_path"])
        if not found:
            raise DeriveError("amount_missing")
        if amount_spec["unit"] == "cents":
            if isinstance(raw, bool) or not isinstance(raw, (int, float)):
                raise DeriveError("amount_unreadable")
            if isinstance(raw, float) and not raw.is_integer():
                raise DeriveError("amount_unreadable")
            cents = int(raw)
            if cents < 0 or cents > int(MAX_AMOUNT_USD * 100):
                raise DeriveError("amount_unreadable")
            amount = cents / 100.0
        else:
            amount = _cents(raw) / 100.0
        if math.isnan(amount) or math.isinf(amount) or amount > MAX_AMOUNT_USD:
            raise DeriveError("amount_unreadable")
        currency_path = amount_spec.get("currency_path")
        if currency_path:
            seen, currency = lookup(arguments, currency_path)
            if not seen or not isinstance(currency, str) or currency.strip().casefold() != "usd":
                raise DeriveError("amount_unit_rejected")
    parties: list[str] = []
    for entry in spec.get("counterparties") or []:
        found, raw = lookup(arguments, entry["json_path"])
        if not found:
            raise DeriveError("counterparty_missing")
        parties.extend(_parties_at(raw))
    if spec.get("deny_unmapped") is True and _unmapped(arguments, _declared_paths(spec)):
        raise DeriveError("unmapped_field")
    return Derived(
        amount_usd=amount,
        counterparties=tuple(sorted(set(parties))),
        irreversible=bool(spec["irreversible"]),
        data_class_floor=str(spec["data_class_floor"]),
    )


def join_data_class(claimed: str, floor: str) -> str:
    """Return the stricter class. Two different middle classes become classified.

    The order is public, then personal/medical/financial, then classified.
    A floor never lowers a claim, and a claim never lowers a floor.
    """
    if claimed not in DATA_CLASSES or floor not in DATA_CLASSES:
        raise DeriveError("data_class_unreadable")
    if claimed == floor:
        return claimed
    middle = {"personal", "medical", "financial"}
    if claimed in middle and floor in middle:
        return "classified"
    rank = {"public": 0, "personal": 1, "medical": 1, "financial": 1, "classified": 2}
    return claimed if rank[claimed] > rank[floor] else floor


def blocked_from_rules(rules: list) -> set[str]:
    found: set[str] = set()
    for rule in rules:
        parties = rule.get("deny_counterparties") if isinstance(rule, Mapping) else None
        if parties:
            found.update(parties)
    return found


def vm_counterparty(parties: tuple[str, ...], blocked: set[str]) -> str:
    """One string for the policy VM. Prefer a blocked party so Path A can deny it."""
    if not parties:
        return ""
    hits = sorted(set(parties) & blocked)
    if hits:
        return hits[0]
    return parties[0]


def disagreement(proposed: Mapping[str, Any], derived: Derived) -> str | None:
    """A present claim that is not what the bytes say. Omission is not a lie."""
    if not isinstance(proposed, Mapping):
        return "malformed_action"
    if "amount_usd" in proposed:
        try:
            claimed_cents = _cents(proposed["amount_usd"])
            derived_cents = 0 if derived.amount_usd is None else _cents(derived.amount_usd)
        except DeriveError as exc:
            return exc.reason
        if claimed_cents != derived_cents:
            return "amount_mismatch"
    elif derived.amount_usd is not None:
        pass
    if "counterparty" in proposed and str(proposed.get("counterparty") or "").strip():
        claimed = str(proposed["counterparty"]).strip().casefold()
        if set(derived.counterparties) != {claimed}:
            return "counterparty_mismatch"
    if "irreversible" in proposed and proposed["irreversible"] is not derived.irreversible:
        return "irreversible_mismatch"
    return None


def form_for(derived: Derived, claimed_data_class: str, blocked: set[str]) -> dict[str, Any]:
    """The form Path A saw. Amount and parties come from the bytes, not the claim."""
    if derived.counterparties:
        party = vm_counterparty(derived.counterparties, blocked)
    else:
        party = ""
    amount = 0.0 if derived.amount_usd is None else derived.amount_usd
    return {
        "amount_usd": amount,
        "data_class": join_data_class(claimed_data_class, derived.data_class_floor),
        "counterparty": party,
        "irreversible": derived.irreversible,
        "counterparties": list(derived.counterparties),
    }


def forms_match(signed: Mapping[str, Any], fresh: Mapping[str, Any]) -> bool:
    if set(signed) != set(fresh):
        return False
    if _cents(signed["amount_usd"]) != _cents(fresh["amount_usd"]):
        return False
    for key in ("data_class", "counterparty", "irreversible"):
        if signed[key] != fresh[key]:
            return False
    if list(signed["counterparties"]) != list(fresh["counterparties"]):
        return False
    return True
