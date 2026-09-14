"""Ed25519 keys and domain-separated authority/device envelopes."""

from __future__ import annotations

import base64
import hashlib
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from .common import canonical_json


ALGORITHM = "Ed25519"


def _write_new(path: Path, data: bytes, mode: int) -> None:
    """Create one regular file without following a link or overwriting a name."""

    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ValueError(f"key directory must be a real directory: {path.parent}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags, mode)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        path.chmod(mode)
    except BaseException:
        path.unlink(missing_ok=True)
        raise


def generate_keypair(private_path: Path, public_path: Path) -> str:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    private_data = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_data = public_key.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_new(private_path, private_data, 0o600)
    try:
        _write_new(public_path, public_data, 0o644)
    except BaseException:
        private_path.unlink(missing_ok=True)
        raise
    return public_key_id(public_key)


def load_private(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise TypeError(f"{path} does not contain an Ed25519 private key")
    return key


def load_public(path: Path) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(path.read_bytes())
    if not isinstance(key, Ed25519PublicKey):
        raise TypeError(f"{path} does not contain an Ed25519 public key")
    return key


def public_key_raw(key: Ed25519PublicKey) -> bytes:
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw,
    )


def public_key_id(key: Ed25519PublicKey) -> str:
    return hashlib.sha256(b"ZKCFA/key/id\x00" + public_key_raw(key)).hexdigest()


def public_key_b64(key: Ed25519PublicKey) -> str:
    return base64.b64encode(public_key_raw(key)).decode("ascii")


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    raw = base64.b64decode(value, validate=True)
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return Ed25519PublicKey.from_public_bytes(raw)


def sign_domain_envelope(
    payload: dict[str, Any],
    private_key: Ed25519PrivateKey,
    *,
    domain: bytes,
) -> dict[str, Any]:
    """Sign a payload in a NUL-terminated protocol domain."""

    if not domain or not domain.endswith(b"\x00"):
        raise ValueError("signature domain must be nonempty and NUL terminated")
    signature = private_key.sign(domain + canonical_json(payload))
    return {
        "algorithm": ALGORITHM,
        "key_id": public_key_id(private_key.public_key()),
        "payload": payload,
        "signature": base64.b64encode(signature).decode("ascii"),
    }


def verify_domain_envelope(
    envelope: object,
    public_key: Ed25519PublicKey,
    *,
    domain: bytes,
    expected_key_id: str | None = None,
) -> dict[str, Any]:
    """Verify the exact envelope shape over ``domain || canonical_json(payload)``."""

    if not domain or not domain.endswith(b"\x00"):
        raise ValueError("signature domain must be nonempty and NUL terminated")
    if not isinstance(envelope, dict):
        raise ValueError("signed envelope must be an object")
    if set(envelope) != {"algorithm", "key_id", "payload", "signature"}:
        raise ValueError("signed envelope has missing or unknown fields")
    if envelope.get("algorithm") != ALGORITHM:
        raise ValueError("unsupported signature algorithm")
    key_id = public_key_id(public_key)
    if envelope.get("key_id") != key_id:
        raise ValueError("envelope key identifier does not match public key")
    if expected_key_id is not None and key_id != expected_key_id:
        raise ValueError("unexpected signing key")
    payload = envelope.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("signed envelope payload must be an object")
    try:
        signature = base64.b64decode(envelope.get("signature", ""), validate=True)
        public_key.verify(signature, domain + canonical_json(payload))
    except (ValueError, InvalidSignature) as error:
        raise ValueError("invalid Ed25519 signature") from error
    return payload
