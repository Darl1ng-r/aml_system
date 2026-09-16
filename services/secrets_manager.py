"""
Secrets Manager & Key Rotation Service
=======================================
Resolution priority (highest to lowest):
  1. HashiCorp Vault via SecretStore (loaded at startup by VaultSecretsLoader)
  2. Mounted secret file  (/var/run/secrets/...)
  3. Environment variable
  4. Pydantic settings default

Features:
  - Multi-key JWT signature verification for zero-downtime key rotation.
  - SecretStore-first resolution with env-var fallback for dev.
  - Hot-reload: Vault renewal task updates SecretStore in-place without restart.
"""

import logging
import os
import jwt
from typing import List, Optional
from config import settings

logger = logging.getLogger(__name__)


def _secret_store():
    """Lazy import to avoid circular dependency at module load time."""
    from services.vault_loader import SecretStore
    return SecretStore


_jwt_fallback_keys: List[str] = []


def _read_secret_file(file_path: str) -> Optional[str]:
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception as e:
            logger.warning(f"Failed to read secret file {file_path}: {e}")
    return None


import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

_cached_rsa_private_pem: Optional[str] = None
_cached_rsa_public_pem: Optional[str] = None


def _int_to_base64url(val: int) -> str:
    b = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')


def get_or_create_rsa_keypair() -> tuple[str, str]:
    """
    Retrieves or generates the active RSA-2048 keypair for RS256 asymmetric signing.
    Resolution priority:
      1. HashiCorp Vault Transit / SecretStore ('jwt.rsa_private_key')
      2. Mounted secret file (/var/run/secrets/jwt_rsa_private_key)
      3. Environment variable (JWT_PRIVATE_KEY_PEM)
      4. Auto-generated in-memory keypair for runtime/dev
    """
    global _cached_rsa_private_pem, _cached_rsa_public_pem
    if _cached_rsa_private_pem and _cached_rsa_public_pem:
        return _cached_rsa_private_pem, _cached_rsa_public_pem

    # 1. Check Vault SecretStore
    vault_priv = _secret_store().get("jwt.rsa_private_key")
    if vault_priv:
        try:
            priv_key = serialization.load_pem_private_key(vault_priv.encode(), password=None)
            pub_key = priv_key.public_key()
            pub_pem = pub_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            _cached_rsa_private_pem = vault_priv
            _cached_rsa_public_pem = pub_pem
            return _cached_rsa_private_pem, _cached_rsa_public_pem
        except Exception as e:
            logger.warning(f"Failed to parse Vault RSA private key: {e}")

    # 2. Check mounted secret file
    file_priv = _read_secret_file("/var/run/secrets/jwt_rsa_private_key")
    if file_priv:
        try:
            priv_key = serialization.load_pem_private_key(file_priv.encode(), password=None)
            pub_key = priv_key.public_key()
            pub_pem = pub_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            _cached_rsa_private_pem = file_priv
            _cached_rsa_public_pem = pub_pem
            return _cached_rsa_private_pem, _cached_rsa_public_pem
        except Exception as e:
            logger.warning(f"Failed to parse mounted RSA private key: {e}")

    # 3. Check environment variable
    env_priv = os.getenv("JWT_PRIVATE_KEY_PEM")
    if env_priv:
        try:
            priv_key = serialization.load_pem_private_key(env_priv.encode(), password=None)
            pub_key = priv_key.public_key()
            pub_pem = pub_key.public_bytes(
                serialization.Encoding.PEM,
                serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
            _cached_rsa_private_pem = env_priv
            _cached_rsa_public_pem = pub_pem
            return _cached_rsa_private_pem, _cached_rsa_public_pem
        except Exception as e:
            logger.warning(f"Failed to parse JWT_PRIVATE_KEY_PEM: {e}")

    # 4. Check environment: ephemeral in-memory keys are strictly forbidden in production
    env = os.getenv("ENVIRONMENT", getattr(settings, "environment", "development")).lower()
    if env == "production":
        raise RuntimeError(
            "CRITICAL SECURITY FAILURE: Ephemeral in-memory RSA key generation is strictly forbidden in production! "
            "Mount an RSA private key file at /var/run/secrets/jwt/private.pem, provide JWT_PRIVATE_KEY_PEM in the "
            "environment, or configure HashiCorp Vault. Ephemeral keys cause multi-pod token signature desynchronization."
        )

    # 5. Generate persistent keypair in memory for local development / testing only
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub = key.public_key()
    _cached_rsa_private_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()
    ).decode()
    _cached_rsa_public_pem = pub.public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return _cached_rsa_private_pem, _cached_rsa_public_pem


def get_jwks() -> dict:
    """Returns RFC 7517 compliant JSON Web Key Set (JWKS) publishing public keys."""
    _, pub_pem = get_or_create_rsa_keypair()
    pub_key = serialization.load_pem_public_key(pub_pem.encode())
    numbers = pub_key.public_numbers()
    kid = "aml-rsa-" + hashlib.sha256(pub_pem.encode()).hexdigest()[:12]

    return {
        "keys": [
            {
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "kid": kid,
                "n": _int_to_base64url(numbers.n),
                "e": _int_to_base64url(numbers.e)
            }
        ]
    }


def get_jwt_signing_key() -> str:
    """Returns the primary active key for signing NEW JWT tokens.
    For RS256, returns the RSA private key PEM.
    For HS256, returns the symmetric secret key."""
    if settings.jwt_algorithm == "RS256":
        priv_pem, _ = get_or_create_rsa_keypair()
        return priv_pem

    vault_keys_str = _secret_store().get("jwt.secret_keys", "")
    if vault_keys_str:
        keys = [k.strip() for k in vault_keys_str.split(",") if k.strip()]
        if keys:
            return keys[0]

    file_secret = _read_secret_file("/var/run/secrets/jwt_secret")
    if file_secret:
        return file_secret

    keys_str = os.getenv("JWT_SECRET_KEYS", "")
    if keys_str:
        keys = [k.strip() for k in keys_str.split(",") if k.strip()]
        if keys:
            return keys[0]

    if settings.jwt_secret_key:
        return settings.jwt_secret_key

    env = os.getenv("ENVIRONMENT", "development").lower()
    if env in ["production", "prod", "staging"]:
        raise RuntimeError("CRITICAL SECURITY VIOLATION: No JWT secret key configured for production environment.")

    return "default_development_secret_change_in_prod"


def get_jwt_verification_keys() -> List[str]:
    """Returns ordered list of valid keys for verifying existing tokens.
    Supports zero-downtime rotation across asymmetric RSA public keys and legacy HMAC keys."""
    keys: List[str] = []

    # 1. Asymmetric RSA public key
    _, pub_pem = get_or_create_rsa_keypair()
    if pub_pem not in keys:
        keys.append(pub_pem)

    # 2. Vault symmetric keys
    vault_keys_str = _secret_store().get("jwt.secret_keys", "")
    if vault_keys_str:
        for k in vault_keys_str.split(","):
            cleaned = k.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)

    # 3. Environment symmetric keys
    keys_env = os.getenv("JWT_SECRET_KEYS", "")
    if keys_env:
        for k in keys_env.split(","):
            cleaned = k.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)

    for fk in _jwt_fallback_keys:
        if fk and fk not in keys:
            keys.append(fk)

    if settings.jwt_secret_key and settings.jwt_secret_key not in keys:
        keys.append(settings.jwt_secret_key)

    return keys


def register_fallback_jwt_secret(old_secret: str) -> None:
    if old_secret and old_secret not in _jwt_fallback_keys:
        _jwt_fallback_keys.append(old_secret)
        logger.info("Registered fallback JWT secret for key rotation verification.")


def decode_jwt_with_rotation(token: str, algorithm: str | None = None) -> dict:
    """Decodes and verifies a JWT token against active RSA public keys and fallback keys."""
    verification_keys = get_jwt_verification_keys()
    algorithms = [algorithm] if algorithm else [settings.jwt_algorithm, "RS256", "HS256"]
    if "RS256" not in algorithms:
        algorithms.append("RS256")
    if "HS256" not in algorithms:
        algorithms.append("HS256")

    last_exception = None

    for key in verification_keys:
        try:
            payload = jwt.decode(token, key, algorithms=algorithms)
            return payload
        except jwt.InvalidSignatureError as e:
            last_exception = e
            continue
        except jwt.PyJWTError as e:
            last_exception = e
            continue

    if last_exception:
        raise last_exception
    raise jwt.PyJWTError("Failed to verify token with any configured secret key.")


def get_postgres_password() -> str:
    """Resolves PostgreSQL password. Resolution: Vault -> mounted file -> env -> settings."""
    vault_pw = _secret_store().get("postgres.password")
    if vault_pw:
        return vault_pw

    file_password = _read_secret_file("/var/run/secrets/postgres_password")
    if file_password:
        return file_password

    if settings.postgres_user == "aml_app" and (settings.aml_app_password or os.getenv("AML_APP_PASSWORD")):
        return settings.aml_app_password or os.getenv("AML_APP_PASSWORD", "")

    return settings.postgres_password or os.getenv("POSTGRES_PASSWORD", "postgrespassword")


def get_postgres_dsn() -> str:
    """Dynamically builds PostgreSQL DSN using credentials from Vault or env."""
    store = _secret_store()
    user = store.get("postgres.user") or settings.postgres_user
    host = store.get("postgres.host") or settings.postgres_host
    port = store.get("postgres.port") or str(settings.postgres_port)
    db   = store.get("postgres.db")   or settings.postgres_db
    password = get_postgres_password()
    return f"postgresql://{user}:{password}@{host}:{port}/{db}"
