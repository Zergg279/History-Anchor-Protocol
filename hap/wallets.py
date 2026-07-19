from __future__ import annotations

import base64
import os
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .crypto import derive_public_key, generate_keypair, public_key_to_author_id

WALLET_SCHEMA = "hap.wallet"
WALLET_VERSION = 1
SCRYPT_N = 2**15
SCRYPT_R = 8
SCRYPT_P = 1


class WalletError(ValueError):
    pass


def _b64e(value: bytes) -> str:
    return base64.b64encode(value).decode("ascii")


def _b64d(value: str) -> bytes:
    return base64.b64decode(value, validate=True)


def _derive_key(password: str, salt: bytes, *, n: int, r: int, p: int) -> bytes:
    if not password:
        raise WalletError("wallet password cannot be empty")
    kdf = Scrypt(salt=salt, length=32, n=n, r=r, p=p)
    return kdf.derive(password.encode("utf-8"))


def create_encrypted_wallet(password: str) -> dict[str, Any]:
    keypair = generate_keypair()
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    aad = f"{WALLET_SCHEMA}:{WALLET_VERSION}:{keypair.public_key}".encode("ascii")
    ciphertext = AESGCM(key).encrypt(nonce, keypair.private_key.encode("ascii"), aad)
    return {
        "schema": WALLET_SCHEMA,
        "version": WALLET_VERSION,
        "author_id": keypair.author_id,
        "public_key": keypair.public_key,
        "kdf": {
            "name": "scrypt",
            "salt": _b64e(salt),
            "n": SCRYPT_N,
            "r": SCRYPT_R,
            "p": SCRYPT_P,
        },
        "cipher": {
            "name": "aes-256-gcm",
            "nonce": _b64e(nonce),
            "ciphertext": _b64e(ciphertext),
        },
    }


def decrypt_wallet(wallet: dict[str, Any], password: str) -> str:
    try:
        if (
            wallet.get("schema") != WALLET_SCHEMA
            or wallet.get("version") != WALLET_VERSION
        ):
            raise WalletError("unsupported wallet format")
        public_key = wallet["public_key"]
        if public_key_to_author_id(public_key) != wallet["author_id"]:
            raise WalletError("wallet author_id does not match public key")
        kdf_spec = wallet["kdf"]
        cipher_spec = wallet["cipher"]
        if kdf_spec.get("name") != "scrypt" or cipher_spec.get("name") != "aes-256-gcm":
            raise WalletError("unsupported wallet encryption")
        n = int(kdf_spec["n"])
        r = int(kdf_spec["r"])
        p = int(kdf_spec["p"])
        if n < 2**14 or n > 2**20 or r < 1 or r > 32 or p < 1 or p > 16:
            raise WalletError("unsafe wallet KDF parameters")
        key = _derive_key(password, _b64d(kdf_spec["salt"]), n=n, r=r, p=p)
        aad = f"{WALLET_SCHEMA}:{WALLET_VERSION}:{public_key}".encode("ascii")
        private_key = (
            AESGCM(key)
            .decrypt(
                _b64d(cipher_spec["nonce"]),
                _b64d(cipher_spec["ciphertext"]),
                aad,
            )
            .decode("ascii")
        )
        if derive_public_key(private_key) != public_key:
            raise WalletError("wallet private key does not match public key")
        return private_key
    except WalletError:
        raise
    except Exception as exc:
        raise WalletError(
            "wallet could not be decrypted; password or file may be wrong"
        ) from exc
