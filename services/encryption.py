"""
Field-Level PII Encryption Service (GAP-20)
===========================================
Provides NIST-compliant AES-256-GCM authenticated field encryption for sensitive PII
(Tax IDs, Social Security Numbers, Dates of Birth) stored in PostgreSQL.
"""

import base64
import hashlib
import os
import secrets
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from config import settings


def _get_encryption_key() -> bytes:
    """Derives a consistent 256-bit AES-GCM encryption key from Vault or JWT secret."""
    try:
        from services.vault_loader import SecretStore
        vault_key = SecretStore.get("encryption.field_key")
        if vault_key:
            return hashlib.sha256(vault_key.encode("utf-8")).digest()
    except Exception:
        pass

    raw = getattr(settings, "jwt_secret_key", "") or os.getenv("JWT_SECRET_KEY", "default_master_encryption_key_2026")
    return hashlib.sha256(raw.encode("utf-8")).digest()


def encrypt_pii(plaintext: Optional[str]) -> Optional[str]:
    """
    Encrypts a sensitive PII string using AES-256-GCM.
    Returns:
        Base64-encoded string containing (12-byte nonce + ciphertext + 16-byte auth tag).
    """
    if not plaintext:
        return plaintext

    key = _get_encryption_key()
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit unique nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_pii(ciphertext_b64: Optional[str]) -> Optional[str]:
    """
    Decrypts and authenticates a Base64-encoded AES-256-GCM ciphertext payload.
    """
    if not ciphertext_b64:
        return ciphertext_b64

    try:
        raw = base64.b64decode(ciphertext_b64.encode("utf-8"))
        if len(raw) < 28:  # 12-byte nonce + 16-byte tag minimum
            return ciphertext_b64

        nonce = raw[:12]
        ciphertext = raw[12:]
        key = _get_encryption_key()
        aesgcm = AESGCM(key)
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode("utf-8")
    except Exception:
        # If decryption fails (e.g. unencrypted legacy value), return as-is
        return ciphertext_b64
