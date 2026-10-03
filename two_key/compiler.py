"""Compile one constitution into Path A bytecode and Path B prose."""

from __future__ import annotations

from dataclasses import dataclass

from .canonical import canonical_hash
from .constitution import validate_tool_specs
from .policy_vm import ConstitutionError, compile_constitution


@dataclass(frozen=True)
class CompiledConstitution:
    bytecode: list[tuple]
    bytecode_hash: str
    judge_text: str
    nl_hash: str
    rules: list[dict]
    tool_specs: dict
    specs_enforced: bool
    spec_hash: str


def compile_both(prose: str, rules: list, tool_specs: dict | None = None, *,
                 specs_enforced: bool = False, max_steps: int = 4096) -> CompiledConstitution:
    if not isinstance(prose, str) or not prose.strip():
        raise ConstitutionError("constitution prose (the Path B text) is empty")
    if specs_enforced:
        specs = validate_tool_specs(tool_specs or {}, rules)
        spec_hash = canonical_hash(specs)
    else:
        specs = {}
        spec_hash = ""
    bytecode = compile_constitution(rules, max_steps=max_steps)
    return CompiledConstitution(
        bytecode=bytecode,
        bytecode_hash=canonical_hash([[op, *rest] for op, *rest in bytecode]),
        judge_text=prose,
        nl_hash=canonical_hash(prose),
        rules=list(rules),
        tool_specs=specs,
        specs_enforced=specs_enforced,
        spec_hash=spec_hash,
    )