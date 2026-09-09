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


def get_jwt_signing_key() -> str:
    """Returns the primary active secret key for signing NEW JWT tokens.
    Resolution: Vault SecretStore -> mounted file -> env var -> settings default."""
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
    Supports zero-downtime rotation."""
    keys: List[str] = []

    primary = get_jwt_signing_key()
    if primary:
        keys.append(primary)

    vault_keys_str = _secret_store().get("jwt.secret_keys", "")
    if vault_keys_str:
        for k in vault_keys_str.split(","):
            cleaned = k.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)

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


def decode_jwt_with_rotation(token: str, algorithm: str = "HS256") -> dict:
    """Decodes and verifies a JWT token against active and all fallback keys."""
    verification_keys = get_jwt_verification_keys()
    last_exception = None

    for key in verification_keys:
        try:
            payload = jwt.decode(token, key, algorithms=[algorithm])
            return payload
        except jwt.InvalidSignatureError as e:
            last_exception = e
            continue
        except jwt.PyJWTError as e:
            raise e

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
