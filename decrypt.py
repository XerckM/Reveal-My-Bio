#!/usr/bin/env python3
"""Decrypt the biography. Run with: python decrypt_bio.py"""

import base64
import hashlib
import zlib

try:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise SystemExit("Install the dependency: python -m pip install cryptography")

TOKEN = ("INSERT TOKEN HERE")


def decrypt_biography(token: str, passphrase: str) -> str:
    """Authenticate, decrypt, decompress, and return the biography."""
    raw = base64.b64decode("".join(token.split()), validate=True)
    if len(raw) < 28:
        raise ValueError("Expected a 12-byte nonce and a 16-byte tag at minimum.")

    # Use the first 16 bytes of the raw SHA-256 digest, not its hexadecimal text.
    key = hashlib.sha256(passphrase.encode("utf-8")).digest()[:16]
    nonce = raw[:12]
    ciphertext_and_tag = raw[12:]

    # AESGCM expects the tag appended to the ciphertext. None means no AAD.
    compressed = AESGCM(key).decrypt(nonce, ciphertext_and_tag, None)
    return zlib.decompress(compressed).decode("utf-8")


if __name__ == "__main__":
    try:
        passphrase = input("Passphrase: ")
        print("\n" + decrypt_biography(TOKEN, passphrase))
    except InvalidTag:
        raise SystemExit("Decryption failed: incorrect passphrase or altered ciphertext.")
    except (ValueError, zlib.error) as exc:
        raise SystemExit(f"Invalid encrypted data: {exc}")
    except (EOFError, KeyboardInterrupt):
        raise SystemExit("\nCancelled.")
