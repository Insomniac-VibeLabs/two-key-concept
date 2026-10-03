"""Append-only hash-chained ledger with a signed head.

This is the concept ledger: integrity and single-use redemption. It does not
encrypt at rest, anchor to a chain, or scan payloads.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .canonical import canonical_bytes, canonical_hash
from .keys import public_from_raw, public_raw, sign, verify


class LedgerError(RuntimeError):
    pass


def _merkle(leaves: list[bytes]) -> bytes:
    if not leaves:
        return hashlib.sha256(b"empty").digest()
    level = [hashlib.sha256(b"\x00" + leaf).digest() for leaf in leaves]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(b"\x01" + level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0]


@dataclass(frozen=True)
class Entry:
    seq: int
    prev: str
    kind: str
    body: dict
    entry_hash: str

    def to_json(self) -> dict:
        return {"seq": self.seq, "prev": self.prev, "kind": self.kind,
                "body": self.body, "entry_hash": self.entry_hash}


class Ledger:
    def __init__(self, path: Path | str, private_key, public_key=None):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        self.private_key = private_key
        self.public_key = public_key or private_key.public_key()
        self._lock = threading.Lock()
        self.entries: list[Entry] = []
        self._redeemed: set[str] = set()
        self._load()

    @property
    def entries_path(self) -> Path:
        return self.path / "entries.jsonl"

    @property
    def head_path(self) -> Path:
        return self.path / "head.json"

    def _load(self) -> None:
        if not self.entries_path.exists():
            return
        prev = "0" * 64
        for line in self.entries_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(line)
            entry = Entry(raw["seq"], raw["prev"], raw["kind"], raw["body"], raw["entry_hash"])
            expect = self._hash(entry.seq, entry.prev, entry.kind, entry.body)
            if entry.entry_hash != expect or entry.prev != prev or entry.seq != len(self.entries):
                raise LedgerError("ledger chain failed verification")
            self.entries.append(entry)
            prev = entry.entry_hash
            if entry.kind == "redemption":
                self._redeemed.add(entry.body["jti"])
        self._verify_head()

    def _hash(self, seq: int, prev: str, kind: str, body: dict) -> str:
        return canonical_hash({"seq": seq, "prev": prev, "kind": kind, "body": body})

    def append(self, kind: str, body: dict) -> Entry:
        if not isinstance(body, dict):
            raise LedgerError("ledger body must be an object")
        with self._lock:
            prev = self.entries[-1].entry_hash if self.entries else "0" * 64
            seq = len(self.entries)
            entry_hash = self._hash(seq, prev, kind, body)
            entry = Entry(seq, prev, kind, body, entry_hash)
            line = json.dumps(entry.to_json(), separators=(",", ":"), sort_keys=True)
            with self.entries_path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
                fh.flush()
                os.fsync(fh.fileno())
            self.entries.append(entry)
            if kind == "redemption":
                self._redeemed.add(body["jti"])
            return entry

    def checkpoint(self) -> dict:
        with self._lock:
            head = {
                "size": len(self.entries),
                "tip": self.entries[-1].entry_hash if self.entries else "0" * 64,
                "merkle_root": self.merkle_root(),
                "public_key": public_raw(self.public_key),
            }
            signed = canonical_bytes(head)
            head["signature"] = sign(self.private_key, signed)
            tmp = self.head_path.with_suffix(".json.tmp")
            tmp.write_text(json.dumps(head, indent=2) + "\n", encoding="utf-8")
            os.replace(tmp, self.head_path)
            return head

    def _verify_head(self) -> None:
        if not self.entries:
            return
        if not self.head_path.exists():
            raise LedgerError("ledger has entries but no signed head")
        head = json.loads(self.head_path.read_text(encoding="utf-8"))
        body = {k: head[k] for k in ("size", "tip", "merkle_root", "public_key")}
        pub = public_from_raw(body["public_key"])
        if not verify(pub, canonical_bytes(body), head.get("signature") or ""):
            raise LedgerError("signed head failed verification")
        if body["size"] != len(self.entries) or body["tip"] != self.entries[-1].entry_hash:
            raise LedgerError("signed head does not match the chain")
        if body["merkle_root"] != self.merkle_root():
            raise LedgerError("signed head merkle root mismatch")

    def merkle_root(self, size: int | None = None) -> str:
        entries = self.entries if size is None else self.entries[:size]
        leaves = [bytes.fromhex(e.entry_hash) for e in entries]
        return _merkle(leaves).hex()

    def size(self) -> int:
        return len(self.entries)

    def is_redeemed(self, jti: str) -> bool:
        return jti in self._redeemed

    def kinds_after(self, size: int, kinds: set[str]) -> list[Entry]:
        return [e for e in self.entries[size:] if e.kind in kinds]

    def verify(self) -> None:
        prev = "0" * 64
        for i, entry in enumerate(self.entries):
            if entry.seq != i or entry.prev != prev:
                raise LedgerError(f"chain break at {i}")
            if entry.entry_hash != self._hash(entry.seq, entry.prev, entry.kind, entry.body):
                raise LedgerError(f"hash mismatch at {i}")
            prev = entry.entry_hash
        self._verify_head()
