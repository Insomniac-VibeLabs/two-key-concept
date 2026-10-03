"""Compile one constitution into Path A bytecode and Path B prose."""

from __future__ import annotations

from dataclasses import dataclass

from .canonical import canonical_hash
from .policy_vm import ConstitutionError, compile_constitution


@dataclass(frozen=True)
class CompiledConstitution:
    bytecode: list[tuple]
    bytecode_hash: str
    judge_text: str
    nl_hash: str
    rules: list[dict]


def compile_both(prose: str, rules: list, *, max_steps: int = 4096) -> CompiledConstitution:
    if not isinstance(prose, str) or not prose.strip():
        raise ConstitutionError("constitution prose (the Path B text) is empty")
    bytecode = compile_constitution(rules, max_steps=max_steps)
    return CompiledConstitution(
        bytecode=bytecode,
        bytecode_hash=canonical_hash([[op, *rest] for op, *rest in bytecode]),
        judge_text=prose,
        nl_hash=canonical_hash(prose),
        rules=list(rules),
    )
