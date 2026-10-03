"""Signed constitution: prose for Path B, hard rules for Path A."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

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

    @property
    def digest(self) -> str:
        return canonical_hash(self.document["signed"])


def _load_rules(path: Path) -> list:
    text = path.read_text(encoding="utf-8")
    if path.suffix == ".json":
        data = json.loads(text)
    else:
        try:
            import yaml
        except ImportError as e:
            raise ConstitutionError("reading YAML rules needs the yaml extra (pip install pyyaml)") from e
        data = yaml.safe_load(text)
    if isinstance(data, dict) and "hard_rules" in data:
        data = data["hard_rules"]
    if not isinstance(data, list):
        raise ConstitutionError("hard rules must be a list")
    return data


def load_unsigned(prose_path: Path | str, rules_path: Path | str) -> tuple[str, list]:
    prose = Path(prose_path).read_text(encoding="utf-8")
    rules = validate_rules(_load_rules(Path(rules_path)))
    return prose, rules


def sign_constitution(prose: str, rules: list, private_key) -> dict:
    rules = validate_rules(rules)
    signed = {"prose": prose, "hard_rules": rules}
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
    return Constitution(prose, validate_rules(rules), envelope)
