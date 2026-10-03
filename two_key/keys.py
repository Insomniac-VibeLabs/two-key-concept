"""Ed25519 principal keys. The concept line does not implement hybrid ML-DSA."""

from __future__ import annotations

import base64
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def generate_private_key() -> Ed25519PrivateKey:
    return Ed25519PrivateKey.generate()


def public_key(private_key: Ed25519PrivateKey) -> Ed25519PublicKey:
    return private_key.public_key()


def fingerprint(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    import hashlib
    return hashlib.sha256(raw).hexdigest()[:16]


def save_private_key(path: Path | str, private_key: Ed25519PrivateKey) -> None:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    path.chmod(0o600)


def load_private_key(path: Path | str) -> Ed25519PrivateKey:
    data = Path(path).read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("principal key must be Ed25519")
    return key


def save_public_key(path: Path | str, public: Ed25519PublicKey) -> None:
    Path(path).write_bytes(public.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))


def load_public_key(path: Path | str) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(Path(path).read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("public key must be Ed25519")
    return key


def public_raw(public: Ed25519PublicKey) -> str:
    return base64.b64encode(public.public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode("ascii")


def public_from_raw(raw: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(base64.b64decode(raw))


def sign(private_key: Ed25519PrivateKey, message: bytes) -> str:
    return base64.b64encode(private_key.sign(message)).decode("ascii")


def verify(public: Ed25519PublicKey, message: bytes, signature: str) -> bool:
    try:
        public.verify(base64.b64decode(signature), message)
        return True
    except (InvalidSignature, ValueError):
        return False
