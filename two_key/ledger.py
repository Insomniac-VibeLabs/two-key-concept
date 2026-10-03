"""Append-only hash-chained ledger with a signed head.

Entries and the head are AES-256-GCM ciphertext at rest. The data key is
wrapped by a ledger key that is not the principal key. The head is signed by
the principal and by a witness key. Both of those files live outside the
ledger directory. A stolen principal key can neither decrypt the log nor
sign a new head.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
from dataclasses import dataclass
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .canonical import canonical_bytes, canonical_hash
from .keys import (
    generate_private_key, load_private_key, public_from_raw, public_key,
    public_raw, save_private_key, save_public_key, sign, verify,
)

WRAP_FORMAT = "two-key-concept-ledger-wrap/1"
RECORD_FORMAT = "two-key-concept-ledger-enc/1"
_WRAP_INFO = b"two-key-concept-ledger-wrap/1"
_RECORD_AAD = b"two-key-concept-ledger-enc/1"


class LedgerError(RuntimeError):
    pass


def merkle_root(leaves: list[bytes]) -> bytes:
    """RFC 6962 Merkle tree hash. Empty input is SHA-256("empty"), not a leaf."""

    def mth(items: list[bytes]) -> bytes:
        n = len(items)
        if n == 0:
            return hashlib.sha256(b"empty").digest()
        if n == 1:
            return hashlib.sha256(b"\x00" + items[0]).digest()
        k = 1 << (n.bit_length() - 1)
        if k == n:
            k >>= 1
        return hashlib.sha256(b"\x01" + mth(items[:k]) + mth(items[k:])).digest()

    return mth(leaves)


def _kek(ledger_key: bytes) -> bytes:
    if len(ledger_key) != 32:
        raise LedgerError("ledger key must be 32 bytes")
    return HKDF(SHA256(), 32, salt=b"two-key-concept-ledger", info=_WRAP_INFO).derive(ledger_key)


def _seal(data_key: bytes, plaintext: str) -> str:
    nonce = os.urandom(12)
    ct = AESGCM(data_key).encrypt(nonce, plaintext.encode("utf-8"), _RECORD_AAD)
    return json.dumps({"enc": RECORD_FORMAT, "n": nonce.hex(), "c": ct.hex()}, separators=(",", ":"))


def _open(data_key: bytes, record: str) -> str:
    try:
        blob = json.loads(record)
        if blob.get("enc") != RECORD_FORMAT:
            raise LedgerError("ledger record is not encrypted")
        return AESGCM(data_key).decrypt(
            bytes.fromhex(blob["n"]), bytes.fromhex(blob["c"]), _RECORD_AAD).decode("utf-8")
    except LedgerError:
        raise
    except Exception as e:
        raise LedgerError("ledger record rejected (wrong key or tampered ciphertext)") from e


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
    def __init__(self, path: Path | str, private_key, public_key=None, *,
                 witness_path: Path | str | None = None, ledger_key_path: Path | str | None = None):
        self.path = Path(path)
        self.path.mkdir(parents=True, exist_ok=True)
        if self.path.resolve() == self.path.parent.resolve():
            raise LedgerError("ledger path must be a directory, not a filesystem root")
        self.private_key = private_key
        self.public_key = public_key or private_key.public_key()
        self.witness_path = Path(witness_path) if witness_path else self.path.parent / f"{self.path.name}.witness" / "witness.pem"
        self.ledger_key_path = Path(ledger_key_path) if ledger_key_path else self.path.parent / f"{self.path.name}.ledger-key" / "ledger.key"
        if self.witness_path.resolve().is_relative_to(self.path.resolve()):
            raise LedgerError("witness key must live outside the ledger directory")
        if self.ledger_key_path.resolve().is_relative_to(self.path.resolve()):
            raise LedgerError("ledger key must live outside the ledger directory")
        self._lock = threading.Lock()
        self.entries: list[Entry] = []
        self._redeemed: set[str] = set()
        self._ledger_key = self._open_ledger_key()
        self._data_key = self._open_data_key()
        self._witness = self._open_witness()
        self._load()

    @property
    def entries_path(self) -> Path:
        return self.path / "entries.jsonl"

    @property
    def head_path(self) -> Path:
        return self.path / "head.json"

    @property
    def wrap_path(self) -> Path:
        return self.path / "keywrap.json"

    def _open_ledger_key(self) -> bytes:
        if not self.ledger_key_path.exists():
            if self.wrap_path.exists():
                raise LedgerError("ledger key missing; refusing to open ciphertext with the principal key")
            self.ledger_key_path.parent.mkdir(parents=True, exist_ok=True)
            key = os.urandom(32)
            self.ledger_key_path.write_bytes(key)
            os.chmod(self.ledger_key_path, 0o600)
            return key
        key = self.ledger_key_path.read_bytes()
        if len(key) != 32:
            raise LedgerError("ledger key must be 32 bytes")
        return key

    def _open_data_key(self) -> bytes:
        kek = _kek(self._ledger_key)
        if not self.wrap_path.exists():
            data_key = os.urandom(32)
            nonce = os.urandom(12)
            blob = {"format": WRAP_FORMAT, "nonce": nonce.hex(),
                    "wrapped": AESGCM(kek).encrypt(nonce, data_key, _WRAP_INFO).hex()}
            self.wrap_path.write_text(json.dumps(blob, indent=2) + "\n", encoding="utf-8")
            os.chmod(self.wrap_path, 0o600)
            return data_key
        blob = json.loads(self.wrap_path.read_text(encoding="utf-8"))
        if blob.get("format") != WRAP_FORMAT:
            raise LedgerError("ledger key file is not a concept wrapped data key")
        try:
            return AESGCM(kek).decrypt(bytes.fromhex(blob["nonce"]), bytes.fromhex(blob["wrapped"]), _WRAP_INFO)
        except Exception as e:
            raise LedgerError("ledger data key rejected (wrong ledger key)") from e

    def _open_witness(self):
        if not self.witness_path.exists():
            if self.head_path.exists():
                raise LedgerError("witness key missing; refusing to open a head the principal key alone could replace")
            key = generate_private_key()
            self.witness_path.parent.mkdir(parents=True, exist_ok=True)
            save_private_key(self.witness_path, key)
            save_public_key(self.witness_path.with_suffix(".pub.pem"), public_key(key))
            return key
        return load_private_key(self.witness_path)

    def _load(self) -> None:
        if not self.entries_path.exists():
            return
        prev = "0" * 64
        for line in self.entries_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            raw = json.loads(_open(self._data_key, line))
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
            line = _seal(self._data_key, json.dumps(entry.to_json(), separators=(",", ":"), sort_keys=True))
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
            if not self.witness_path.exists():
                raise LedgerError("witness key missing; refusing to sign a head the principal key alone could forge")
            self._witness = load_private_key(self.witness_path)
            head = {
                "size": len(self.entries),
                "tip": self.entries[-1].entry_hash if self.entries else "0" * 64,
                "merkle_root": self.merkle_root(),
                "public_key": public_raw(self.public_key),
                "witness_public_key": public_raw(self._witness.public_key()),
            }
            signed = canonical_bytes(head)
            stored = dict(head)
            stored["signature"] = sign(self.private_key, signed)
            stored["witness_signature"] = sign(self._witness, signed)
            tmp = self.head_path.with_suffix(".json.tmp")
            tmp.write_text(_seal(self._data_key, json.dumps(stored)) + "\n", encoding="utf-8")
            os.replace(tmp, self.head_path)
            return stored

    def _verify_head(self) -> None:
        if not self.entries:
            return
        if not self.head_path.exists():
            raise LedgerError("ledger has entries but no signed head")
        stored = json.loads(_open(self._data_key, self.head_path.read_text(encoding="utf-8")))
        body = {k: stored[k] for k in ("size", "tip", "merkle_root", "public_key", "witness_public_key")}
        message = canonical_bytes(body)
        if not verify(public_from_raw(body["public_key"]), message, stored.get("signature") or ""):
            raise LedgerError("principal head signature failed")
        if not verify(public_from_raw(body["witness_public_key"]), message, stored.get("witness_signature") or ""):
            raise LedgerError("witness head signature failed")
        if body["public_key"] != public_raw(self.public_key):
            raise LedgerError("head principal key does not match the ledger key")
        if body["size"] != len(self.entries) or body["tip"] != self.entries[-1].entry_hash:
            raise LedgerError("signed head does not match the chain")
        if body["merkle_root"] != self.merkle_root():
            raise LedgerError("signed head merkle root mismatch")

    def merkle_root(self, size: int | None = None) -> str:
        entries = self.entries if size is None else self.entries[:size]
        leaves = [bytes.fromhex(e.entry_hash) for e in entries]
        return merkle_root(leaves).hex()

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
