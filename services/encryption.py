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

ENCRYPTION_VERSION_PREFIX = "enc:v1:"


class DecryptionError(ValueError):
    """Raised when an authenticated AES-256-GCM PII payload fails integrity verification."""


def _derive_aes_key(
    key_material: str,
    info: bytes = b"aml-pii-field-encryption-v1",
    tenant_id: Optional[str] = None,
) -> bytes:
    """
    Derives a 256-bit (32-byte) AES key from raw key material using RFC 5869 HKDF-SHA256.
    Supports optional per-tenant domain separation salt (NIST SP 800-57).
    """
    salt = (
        f"aml-system-pii-salt-2026:{tenant_id}".encode("utf-8")
        if tenant_id
        else b"aml-system-pii-salt-2026"
    )
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=info,
    )
    return hkdf.derive(key_material.encode("utf-8"))


def _get_encryption_key(tenant_id: Optional[str] = None) -> bytes:
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
            return _derive_aes_key(vault_key, tenant_id=tenant_id)
    except Exception:
        pass

    # 2. Mounted secret file
    secret_file = "/var/run/secrets/pii_encryption_key"
    if os.path.exists(secret_file):
        try:
            with open(secret_file, "r", encoding="utf-8") as f:
                val = f.read().strip()
                if val:
                    return _derive_aes_key(val, tenant_id=tenant_id)
        except Exception as e:
            logger.warning(f"Failed to read mounted secret {secret_file}: {e}")

    # 3. Dedicated environment variable or config setting
    env_key = os.getenv("PII_ENCRYPTION_KEY") or getattr(settings, "pii_encryption_key", None)
    if env_key:
        return _derive_aes_key(env_key, tenant_id=tenant_id)

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
    return _derive_aes_key(
        "dev_insecure_ephemeral_pii_master_key_do_not_use_in_production",
        tenant_id=tenant_id,
    )


def encrypt_pii(plaintext: Optional[str], tenant_id: Optional[str] = None) -> Optional[str]:
    """
    Encrypts a sensitive PII string using AES-256-GCM.
    Returns:
        Versioned string 'enc:v1:<base64(12-byte nonce + ciphertext + 16-byte auth tag)>'.
    """
    if not plaintext:
        return plaintext

    key = _get_encryption_key(tenant_id=tenant_id)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)  # 96-bit unique nonce
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
    return ENCRYPTION_VERSION_PREFIX + base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_pii(
    ciphertext_b64: Optional[str],
    tenant_id: Optional[str] = None,
    allow_legacy_plaintext: bool = False,
) -> Optional[str]:
    """
    Decrypts and authenticates an AES-256-GCM ciphertext payload.
    Raises DecryptionError on tampered or corrupted authenticated ciphertexts
    instead of silently returning raw ciphertext.
    """
    if not ciphertext_b64:
        return ciphertext_b64

    is_versioned = ciphertext_b64.startswith(ENCRYPTION_VERSION_PREFIX)
    b64_body = ciphertext_b64[len(ENCRYPTION_VERSION_PREFIX):] if is_versioned else ciphertext_b64

    try:
        raw = base64.b64decode(b64_body.encode("utf-8"), validate=True)
    except Exception as e:
        if is_versioned or not allow_legacy_plaintext:
            raise DecryptionError(f"Invalid base64 ciphertext payload: {e}") from e
        return ciphertext_b64

    if len(raw) < 28:  # 12-byte nonce + 16-byte tag minimum
        if is_versioned or not allow_legacy_plaintext:
            raise DecryptionError("Ciphertext payload shorter than minimum AES-GCM frame (28 bytes).")
        return ciphertext_b64

    nonce = raw[:12]
    ciphertext = raw[12:]
    key = _get_encryption_key(tenant_id=tenant_id)
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode("utf-8")
    except Exception as e:
        logger.error("AES-256-GCM PII authentication/decryption failure (possible tampering or key mismatch).")
        raise DecryptionError("PII decryption failed: authentication tag mismatch or wrong key.") from e
