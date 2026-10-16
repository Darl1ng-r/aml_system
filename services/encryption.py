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
import logging
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from config import settings

logger = logging.getLogger(__name__)


def _derive_aes_key(key_material: str, info: bytes = b"aml-pii-field-encryption-v1") -> bytes:
    """
    Derives a 256-bit (32-byte) AES key from raw key material using RFC 5869 HKDF-SHA256.
    Ensures cryptographic key isolation (NIST SP 800-57).
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"aml-system-pii-salt-2026",
        info=info,
    )
    return hkdf.derive(key_material.encode("utf-8"))


def _get_encryption_key() -> bytes:
    """
    Derives a 256-bit AES-GCM encryption key dedicated strictly to PII encryption.
    Resolution priority:
      1. HashiCorp Vault: 'encryption.pii_key' or 'encryption.field_key'
      2. Mounted secret file: /var/run/secrets/pii_encryption_key
      3. Environment variable: PII_ENCRYPTION_KEY
      4. Configuration setting: settings.pii_encryption_key
    Fails closed in production if no key is provided.
    """
    # 1. Vault SecretStore
    try:
        from services.vault_loader import SecretStore
        vault_key = SecretStore.get("encryption.pii_key") or SecretStore.get("encryption.field_key")
        if vault_key:
            return _derive_aes_key(vault_key)
    except Exception:
        pass

    # 2. Mounted secret file
    secret_file = "/var/run/secrets/pii_encryption_key"
    if os.path.exists(secret_file):
        try:
            with open(secret_file, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val:
                    return _derive_aes_key(val)
        except Exception as e:
            logger.warning(f"Failed to read mounted secret {secret_file}: {e}")

    # 3. Dedicated environment variable or config setting
    env_key = os.getenv("PII_ENCRYPTION_KEY") or getattr(settings, "pii_encryption_key", None)
    if env_key:
        return _derive_aes_key(env_key)

    # 4. Environment-aware guard: fail closed in production
    is_prod = os.getenv("ENVIRONMENT", "").lower() in ("production", "prod")
    if is_prod:
        raise RuntimeError(
            "FATAL (NIST SP 800-57): PII_ENCRYPTION_KEY is required in production environment. "
            "Reusing JWT secrets or static defaults is prohibited."
        )

    # Development / Testing fallback with explicit warning
    logger.warning(
        "PII_ENCRYPTION_KEY not set. Using ephemeral development key derivation. "
        "DO NOT USE IN PRODUCTION."
    )
    return _derive_aes_key("dev_insecure_ephemeral_pii_master_key_do_not_use_in_production")


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
