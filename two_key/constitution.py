"""Signed constitution: prose for Path B, hard rules for Path A, optional tool specs."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from .action import DATA_CLASSES
from .canonical import canonical_bytes, canonical_hash
from .keys import fingerprint, sign, verify
from .policy_vm import ConstitutionError, validate_rules


class ConstitutionSignatureError(ValueError):
    pass


@dataclass(frozen=True)
class Constitution:
    prose: str
    hard_rules: list[dict]
    document: dict
    tool_specs: dict
    specs_enforced: bool

    @property
    def digest(self) -> str:
        return canonical_hash(self.document["signed"])


_PATH = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*$")


def _json_path(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _PATH.fullmatch(value):
        raise ConstitutionError(f"{where}: json_path must be dotted identifiers")
    return value


def _allow_listed(rules: list) -> list[str]:
    found: list[str] = []
    for rule in rules:
        if not isinstance(rule, Mapping) or "allow_only_tools" not in rule:
            continue
        body = rule["allow_only_tools"]
        if not isinstance(body, list):
            continue
        for item in body:
            if isinstance(item, str) and item.strip():
                name = item.strip().casefold()
                if name not in found:
                    found.append(name)
    return found


def validate_tool_specs(specs: Any, rules: list) -> dict:
    """Canonical tool specs. Every allow-listed tool must have one.

    A spec says how to read the argument bytes. It is not an English scanner.
    ``amount.unit`` is ``usd`` or ``cents``. A currency path, when set, must
    be the string ``usd`` at authorization time or the call is denied.
    """
    if not isinstance(specs, Mapping):
        raise ConstitutionError("tool_specs must be a mapping")
    allowed_keys = {"irreversible", "data_class_floor", "amount", "counterparties"}
    out: dict[str, dict] = {}
    for name, spec in specs.items():
        if not isinstance(name, str) or not name.strip():
            raise ConstitutionError("tool_specs: tool name must be a non-empty string")
        tool = name.strip().casefold()
        if tool in out:
            raise ConstitutionError(f"tool_specs: duplicate tool {tool}")
        if not isinstance(spec, Mapping):
            raise ConstitutionError(f"tool_specs.{tool}: expected a mapping")
        extra = set(spec) - allowed_keys
        if extra:
            raise ConstitutionError(f"tool_specs.{tool}: unknown key(s) {sorted(extra)}")
        if "irreversible" not in spec or not isinstance(spec["irreversible"], bool):
            raise ConstitutionError(f"tool_specs.{tool}.irreversible: expected a boolean")
        floor = spec.get("data_class_floor")
        if not isinstance(floor, str) or floor.strip().casefold() not in DATA_CLASSES:
            raise ConstitutionError(
                f"tool_specs.{tool}.data_class_floor: expected one of {list(DATA_CLASSES)}"
            )
        amount = spec.get("amount")
        amount_out = None
        if amount is not None:
            if not isinstance(amount, Mapping):
                raise ConstitutionError(f"tool_specs.{tool}.amount: expected a mapping")
            amount_extra = set(amount) - {"json_path", "unit", "currency_path"}
            if amount_extra or "json_path" not in amount or "unit" not in amount:
                raise ConstitutionError(
                    f"tool_specs.{tool}.amount: requires json_path and unit (usd or cents)"
                )
            if amount["unit"] not in ("usd", "cents"):
                raise ConstitutionError(f"tool_specs.{tool}.amount.unit: expected usd or cents")
            amount_out = {
                "json_path": _json_path(amount["json_path"], f"tool_specs.{tool}.amount"),
                "unit": amount["unit"],
            }
            if "currency_path" in amount:
                amount_out["currency_path"] = _json_path(
                    amount["currency_path"], f"tool_specs.{tool}.amount"
                )
        parties = spec.get("counterparties", [])
        if not isinstance(parties, list):
            raise ConstitutionError(f"tool_specs.{tool}.counterparties: expected a list")
        party_out = []
        seen_paths: set[str] = set()
        for index, entry in enumerate(parties):
            where = f"tool_specs.{tool}.counterparties[{index}]"
            if not isinstance(entry, Mapping) or set(entry) != {"json_path"}:
                raise ConstitutionError(f"{where}: expected json_path only")
            path = _json_path(entry["json_path"], where)
            if path in seen_paths:
                raise ConstitutionError(f"{where}: duplicate path")
            seen_paths.add(path)
            party_out.append({"json_path": path})
        out[tool] = {
            "irreversible": spec["irreversible"],
            "data_class_floor": floor.strip().casefold(),
            "amount": amount_out,
            "counterparties": party_out,
        }
    allow = _allow_listed(rules)
    missing = [tool for tool in allow if tool not in out]
    if missing:
        raise ConstitutionError(f"tool_specs missing for allow-listed tool(s) {missing}")
    extra_tools = [tool for tool in out if allow and tool not in allow]
    if extra_tools:
        raise ConstitutionError(f"tool_specs for tool(s) not in the allow list: {extra_tools}")
    return out


def load_unsigned(prose_path: Path | str, rules_path: Path | str) -> tuple[str, list, dict | None]:
    """Return prose, hard rules, and tool specs.

    ``tool_specs`` is ``None`` only when the rules file omits the key. That is
    the legacy constitution: the agent's form is still trusted. A present key
    must be a mapping. An empty mapping is enforced, and is refused when an
    allow list exists and a tool has no spec. ``null`` is not the legacy path.
    """
    prose = Path(prose_path).read_text(encoding="utf-8")
    rules, specs = _load_rules_document(Path(rules_path))
    return prose, validate_rules(rules), specs


def _load_rules_document(path: Path) -> tuple[list, dict | None]:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml
        except ImportError as e:
            raise ConstitutionError("reading YAML rules needs the yaml extra (pip install pyyaml)") from e
        data = yaml.safe_load(text)
    if isinstance(data, list):
        return data, None
    if isinstance(data, dict) and "hard_rules" in data:
        extra = set(data) - {"hard_rules", "tool_specs"}
        if extra:
            raise ConstitutionError(f"unknown rules-file key(s) {sorted(extra)}")
        rules = data["hard_rules"]
        if not isinstance(rules, list):
            raise ConstitutionError("hard rules must be a list")
        if "tool_specs" not in data:
            return rules, None
        specs = data["tool_specs"]
        if not isinstance(specs, Mapping):
            raise ConstitutionError("tool_specs must be a mapping")
        return rules, specs
    raise ConstitutionError("hard rules must be a list")


def sign_constitution(prose: str, rules: list, private_key, tool_specs: Any = None) -> dict:
    rules = validate_rules(rules)
    signed: dict[str, Any] = {"prose": prose, "hard_rules": rules}
    if tool_specs is not None:
        signed["tool_specs"] = validate_tool_specs(tool_specs, rules)
    signature = sign(private_key, canonical_bytes(signed))
    return {
        "format": "two-key-concept-constitution-v1",
        "signed": signed,
        "signature": signature,
        "fingerprint": fingerprint(private_key.public_key()),
    }


def save_envelope(path: Path | str, envelope: dict) -> None:
    Path(path).write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")


def load_envelope(path: Path | str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


def verify_signed(envelope: dict, public_key) -> Constitution:
    if not isinstance(envelope, dict) or envelope.get("format") != "two-key-concept-constitution-v1":
        raise ConstitutionSignatureError("unsupported constitution format")
    signed = envelope.get("signed")
    if not isinstance(signed, dict):
        raise ConstitutionSignatureError("missing signed body")
    if not verify(public_key, canonical_bytes(signed), envelope.get("signature") or ""):
        raise ConstitutionSignatureError("constitution signature failed")
    prose = signed.get("prose")
    rules = signed.get("hard_rules")
    if not isinstance(prose, str) or not prose.strip():
        raise ConstitutionError("constitution prose is empty")
    rules = validate_rules(rules)
    if "tool_specs" in signed:
        specs = validate_tool_specs(signed["tool_specs"], rules)
        enforced = True
    else:
        specs = {}
        enforced = False
    return Constitution(prose, rules, envelope, specs, enforced)
