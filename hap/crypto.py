from __future__ import annotations

import base64
import hashlib
from dataclasses import asdict, dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass(frozen=True)
class Keypair:
    private_key: str
    public_key: str
    author_id: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def public_key_to_author_id(public_key_hex: str) -> str:
    raw = bytes.fromhex(public_key_hex)
    digest = hashlib.blake2b(raw, digest_size=20).hexdigest()
    return f"hap1{digest}"


def generate_keypair() -> Keypair:
    private = Ed25519PrivateKey.generate()
    private_raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_raw = private.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    public_hex = public_raw.hex()
    return Keypair(
        private_key=base64.b64encode(private_raw).decode("ascii"),
        public_key=public_hex,
        author_id=public_key_to_author_id(public_hex),
    )


def derive_public_key(private_key_b64: str) -> str:
    private_raw = base64.b64decode(private_key_b64, validate=True)
    private = Ed25519PrivateKey.from_private_bytes(private_raw)
    return (
        private.public_key()
        .public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
        .hex()
    )


def sign(private_key_b64: str, message: bytes) -> str:
    private_raw = base64.b64decode(private_key_b64, validate=True)
    private = Ed25519PrivateKey.from_private_bytes(private_raw)
    return base64.b64encode(private.sign(message)).decode("ascii")


def verify(public_key_hex: str, signature_b64: str, message: bytes) -> bool:
    try:
        public = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public.verify(base64.b64decode(signature_b64, validate=True), message)
        return True
    except Exception:
        return False


def redact_private_key(wallet: dict[str, Any]) -> dict[str, Any]:
    return {key: value for key, value in wallet.items() if key != "private_key"}
