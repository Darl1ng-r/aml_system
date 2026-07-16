"""
Secrets Manager & Key Rotation Service
=======================================
Implements dynamic secret management and zero-downtime key rotation for JWT
secrets and database credentials.

Features:
  - Multi-key JWT signature verification: Token decoding tries active key first,
    then iterates over fallback/previous keys to allow zero-downtime key rotation.
  - Dynamic credential resolution: Reads secrets from env vars, secret files, or
    comma-separated fallback strings.
  - Secret hot-reloading support for Kubernetes mounted secret volumes (/var/run/secrets).
"""

import logging
import os
import json
import jwt
from typing import List, Optional
from config import settings

logger = logging.getLogger(__name__)

# Cache / Memory state for dynamic secret rotation
_jwt_fallback_keys: List[str] = []


def _read_secret_file(file_path: str) -> Optional[str]:
    """Reads secret from a mounted secret file if present."""
    if os.path.exists(file_path):
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read().strip()
        except Exception as e:
            logger.warning(f"Failed to read secret file {file_path}: {e}")
    return None


def get_jwt_signing_key() -> str:
    """
    Returns the primary active secret key for signing NEW JWT tokens.
    Prioritizes:
      1. Mounted secret file at /var/run/secrets/jwt_secret
      2. First key in comma-separated JWT_SECRET_KEYS
      3. settings.jwt_secret_key
    """
    file_secret = _read_secret_file("/var/run/secrets/jwt_secret")
    if file_secret:
        return file_secret

    keys_str = os.getenv("JWT_SECRET_KEYS", "")
    if keys_str:
        keys = [k.strip() for k in keys_str.split(",") if k.strip()]
        if keys:
            return keys[0]

    return settings.jwt_secret_key or "default_development_secret_change_in_prod"


def get_jwt_verification_keys() -> List[str]:
    """
    Returns an ordered list of valid secret keys for VERIFYING existing JWT tokens:
    [active_primary_key, previous_key_1, previous_key_2, ...]

    This supports zero-downtime key rotation — tokens signed with older keys
    will continue to validate until they naturally expire.
    """
    keys: List[str] = []
    
    primary = get_jwt_signing_key()
    if primary:
        keys.append(primary)

    # Check environment variable for multi-key rotation (e.g. "newkey,oldkey1,oldkey2")
    keys_env = os.getenv("JWT_SECRET_KEYS", "")
    if keys_env:
        for k in keys_env.split(","):
            cleaned = k.strip()
            if cleaned and cleaned not in keys:
                keys.append(cleaned)

    # Include in-memory registered fallback keys
    for fk in _jwt_fallback_keys:
        if fk and fk not in keys:
            keys.append(fk)

    # Include default config fallback if distinct
    if settings.jwt_secret_key and settings.jwt_secret_key not in keys:
        keys.append(settings.jwt_secret_key)

    return keys


def register_fallback_jwt_secret(old_secret: str) -> None:
    """Registers an older secret key as a valid fallback for verifying existing tokens."""
    if old_secret and old_secret not in _jwt_fallback_keys:
        _jwt_fallback_keys.append(old_secret)
        logger.info("Registered fallback JWT secret for key rotation verification.")


def decode_jwt_with_rotation(token: str, algorithm: str = "HS256") -> dict:
    """
    Decodes and verifies a JWT token against the active key and all fallback keys.
    Raises jwt.PyJWTError if signature validation fails across all keys.
    """
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
            # For non-signature errors (e.g. ExpiredSignatureError), fail immediately
            raise e

    if last_exception:
        raise last_exception
    raise jwt.PyJWTError("Failed to verify token with any configured secret key.")


def get_postgres_password() -> str:
    """
    Dynamically resolves current PostgreSQL password.
    Supports mounted file (/var/run/secrets/postgres_password) or env variable.
    """
    file_password = _read_secret_file("/var/run/secrets/postgres_password")
    if file_password:
        return file_password
    return settings.postgres_password or os.getenv("POSTGRES_PASSWORD", "postgrespassword")


def get_postgres_dsn() -> str:
    """Dynamically builds PostgreSQL DSN using current password."""
    password = get_postgres_password()
    return (
        f"postgresql://{settings.postgres_user}:{password}"
        f"@{settings.postgres_host}:{settings.postgres_port}/{settings.postgres_db}"
    )
