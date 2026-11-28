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
from typing import List, Optional, Any
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
from urllib.parse import quote_plus
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

_cached_rsa_private_pem: Optional[str] = None
_cached_rsa_public_pem: Optional[str] = None
_cached_rsa_source_digest: Optional[str] = None

# Canonical mounted secret path (with legacy fallback for backward compatibility)
CANONICAL_RSA_KEY_PATHS = (
    "/var/run/secrets/jwt/private.pem",
    "/var/run/secrets/jwt_rsa_private_key",
    "/var/run/secrets/tls/jwt_private.pem",
)


def invalidate_rsa_key_cache() -> None:
    """Clears cached RSA keypair so Vault hot-reload picks up rotated signing keys immediately."""
    global _cached_rsa_private_pem, _cached_rsa_public_pem, _cached_rsa_source_digest
    _cached_rsa_private_pem = None
    _cached_rsa_public_pem = None
    _cached_rsa_source_digest = None


def _int_to_base64url(val: int) -> str:
    b = val.to_bytes((val.bit_length() + 7) // 8, byteorder='big')
    return base64.urlsafe_b64encode(b).decode('ascii').rstrip('=')


def _derive_public_pem(private_pem: str) -> str:
    priv_key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    return priv_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()


def _resolve_configured_rsa_private_pem() -> Optional[str]:
    """Reads configured RSA private key from Vault -> mounted file -> env var."""
    vault_priv = _secret_store().get("jwt.rsa_private_key")
    if vault_priv:
        return vault_priv.strip()

    for path in CANONICAL_RSA_KEY_PATHS:
        file_priv = _read_secret_file(path)
        if file_priv:
            return file_priv

    env_priv = os.getenv("JWT_PRIVATE_KEY_PEM", "").strip()
    if env_priv:
        return env_priv

    return None


def get_or_create_rsa_keypair() -> tuple[str, str]:
    """
    Retrieves or generates the active RSA-2048 keypair for RS256 asymmetric signing.
    Supports hot-reload whenever Vault / mounted file / env updates the active PEM.
    Resolution priority:
      1. HashiCorp Vault SecretStore ('jwt.rsa_private_key')
      2. Mounted secret file (/var/run/secrets/jwt/private.pem + legacy fallbacks)
      3. Environment variable (JWT_PRIVATE_KEY_PEM)
      4. Auto-generated in-memory keypair for local dev / test ONLY
    """
    global _cached_rsa_private_pem, _cached_rsa_public_pem, _cached_rsa_source_digest

    configured_priv = _resolve_configured_rsa_private_pem()
    if configured_priv:
        digest = hashlib.sha256(configured_priv.encode("utf-8")).hexdigest()
        if _cached_rsa_private_pem and _cached_rsa_public_pem and _cached_rsa_source_digest == digest:
            return _cached_rsa_private_pem, _cached_rsa_public_pem
        try:
            pub_pem = _derive_public_pem(configured_priv)
            _cached_rsa_private_pem = configured_priv
            _cached_rsa_public_pem = pub_pem
            _cached_rsa_source_digest = digest
            return _cached_rsa_private_pem, _cached_rsa_public_pem
        except Exception as e:
            logger.warning(f"Failed to parse configured RSA private key: {e}")

    # Check environment: ephemeral in-memory keys are strictly forbidden in production & staging
    env = os.getenv("ENVIRONMENT", getattr(settings, "environment", "development")).strip().lower()
    if env in {"production", "prod", "staging"} or getattr(settings, "is_hardened", settings.is_production):
        raise RuntimeError(
            "CRITICAL SECURITY FAILURE: Ephemeral in-memory RSA key generation is strictly forbidden in production! "
            "Mount an RSA private key file at /var/run/secrets/jwt/private.pem, provide JWT_PRIVATE_KEY_PEM in the "
            "environment, or configure HashiCorp Vault. Ephemeral keys cause multi-pod token signature desynchronization."
        )

    if _cached_rsa_private_pem and _cached_rsa_public_pem and _cached_rsa_source_digest == "ephemeral":
        return _cached_rsa_private_pem, _cached_rsa_public_pem

    # Generate persistent keypair in memory for local development / testing only
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
    _cached_rsa_source_digest = "ephemeral"
    return _cached_rsa_private_pem, _cached_rsa_public_pem


def _get_previous_rsa_public_pems() -> List[str]:
    """Returns previous/grace-period RSA public PEM keys for zero-downtime rotation."""
    pems: List[str] = []
    sources = [
        _secret_store().get("jwt.previous_public_keys", ""),
        _secret_store().get("jwt.previous_public_key_pem", ""),
        os.getenv("JWT_PREVIOUS_PUBLIC_KEY_PEM", ""),
        _read_secret_file("/var/run/secrets/jwt/previous_public.pem") or "",
    ]
    for raw in sources:
        if not raw:
            continue
        # Support multiple PEM blocks concatenated or separated by '||'
        chunks = [c.strip() for c in raw.replace("||", "\n").split("-----END PUBLIC KEY-----") if c.strip()]
        for chunk in chunks:
            candidate = chunk + "\n-----END PUBLIC KEY-----"
            if "-----BEGIN PUBLIC KEY-----" in candidate and candidate not in pems:
                pems.append(candidate)
    return pems


def _rsa_pub_pem_to_jwk(pub_pem: str) -> Optional[dict]:
    try:
        pub_key = serialization.load_pem_public_key(pub_pem.encode())
        numbers = pub_key.public_numbers()
        kid = "aml-rsa-" + hashlib.sha256(pub_pem.encode()).hexdigest()[:12]
        return {
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": _int_to_base64url(numbers.n),
            "e": _int_to_base64url(numbers.e),
        }
    except Exception as exc:
        logger.warning("Skipping invalid RSA public PEM in JWKS: %s", exc)
        return None


def get_jwks() -> dict:
    """Returns RFC 7517 compliant JSON Web Key Set (JWKS) including active + grace-period keys."""
    _, pub_pem = get_or_create_rsa_keypair()
    keys_out: List[dict] = []
    seen_kids: set[str] = set()

    for candidate in [pub_pem, *_get_previous_rsa_public_pems()]:
        jwk = _rsa_pub_pem_to_jwk(candidate)
        if jwk and jwk["kid"] not in seen_kids:
            seen_kids.add(jwk["kid"])
            keys_out.append(jwk)

    return {"keys": keys_out}


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


def _append_keys(target_list: List[str], *sources: Any) -> None:
    for source in sources:
        if not source:
            continue
        if isinstance(source, str):
            items = [k.strip() for k in source.split(",") if k.strip()]
        else:
            items = [k.strip() for k in source if k and str(k).strip()]
        for item in items:
            if item and item not in target_list:
                target_list.append(item)


def get_jwt_verification_keys() -> List[str]:
    """Returns ordered list of valid keys for verifying existing tokens.
    Supports zero-downtime rotation across active + grace-period RSA public keys and legacy HMAC keys."""
    keys: List[str] = []

    # 1. Active + previous/grace-period asymmetric RSA public keys
    _, pub_pem = get_or_create_rsa_keypair()
    if pub_pem:
        keys.append(pub_pem)
    for prev_pem in _get_previous_rsa_public_pems():
        if prev_pem not in keys:
            keys.append(prev_pem)

    # 2. Vault symmetric keys, environment symmetric keys, in-memory fallbacks, and settings key
    _append_keys(
        keys,
        _secret_store().get("jwt.secret_keys", ""),
        os.getenv("JWT_SECRET_KEYS", ""),
        _jwt_fallback_keys,
        settings.jwt_secret_key,
    )

    return keys


def register_fallback_jwt_secret(old_secret: str) -> None:
    if old_secret and old_secret not in _jwt_fallback_keys:
        _jwt_fallback_keys.append(old_secret)
        logger.info("Registered fallback JWT secret for key rotation verification.")


def _is_pem_key(key: str) -> bool:
    return isinstance(key, str) and "-----BEGIN " in key


def decode_jwt_with_rotation(
    token: str,
    algorithm: str | None = None,
    allow_hs256_fallback: bool = False,
) -> dict:
    """
    Decodes and verifies a JWT token against active RSA public keys and legacy symmetric fallback keys.
    Strictly enforces:
      - Algorithm allowlist (RS256, HS256) and exact algorithm matching when `algorithm` is specified
        (unless `allow_hs256_fallback=True` for deliberate zero-downtime migration).
      - Strict asymmetric/symmetric key-to-algorithm binding (blocks RS256->HS256 confusion).
      - Mandatory `exp` claim verification and `iss`/`aud` validation whenever present on token.
    """
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as e:
        raise jwt.InvalidTokenError(f"Malformed JWT header: {e}") from e

    token_alg = str(unverified_header.get("alg", "")).upper()
    allowed_algs = {"RS256", "HS256"}
    if token_alg not in allowed_algs:
        raise jwt.InvalidAlgorithmError(f"Unsupported or unsafe JWT algorithm: '{token_alg}'")

    # Strictly enforce caller's requested algorithm (AUTHN-04)
    if algorithm:
        req_alg = algorithm.upper()
        if req_alg not in allowed_algs:
            raise jwt.InvalidAlgorithmError(f"Unsupported requested algorithm: '{req_alg}'")
        if token_alg != req_alg:
            if not (allow_hs256_fallback and req_alg == "RS256" and token_alg == "HS256"):
                raise jwt.InvalidAlgorithmError(
                    f"JWT algorithm mismatch: token uses '{token_alg}', expected '{req_alg}'."
                )

    verification_keys = get_jwt_verification_keys()
    last_exception = None
    expected_iss = getattr(settings, "jwt_issuer", "aml-sentinel")
    expected_aud = getattr(settings, "jwt_audience", "aml-sentinel-api")

    for key in verification_keys:
        key_is_rsa = _is_pem_key(key)
        # Strict algorithm-to-key binding: never verify an RSA PEM key with HS256 or vice-versa
        if token_alg == "RS256" and not key_is_rsa:
            continue
        if token_alg == "HS256" and key_is_rsa:
            continue

        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=[token_alg],
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_nbf": True,
                    "verify_aud": False,
                    "verify_iss": False,
                    "require": ["exp"],
                },
            )
            # Validate iss / aud strictly whenever present (or always in production)
            tok_iss = payload.get("iss")
            tok_aud = payload.get("aud")
            if tok_iss is not None and tok_iss != expected_iss:
                raise jwt.InvalidIssuerError("Invalid JWT issuer.")
            if tok_aud is not None:
                aud_list = tok_aud if isinstance(tok_aud, list) else [tok_aud]
                if expected_aud not in aud_list:
                    raise jwt.InvalidAudienceError("Invalid JWT audience.")
            if settings.is_production and (tok_iss != expected_iss or tok_aud is None):
                raise jwt.InvalidTokenError("Missing mandatory JWT issuer or audience claim in production.")
            return payload
        except (jwt.InvalidIssuerError, jwt.InvalidAudienceError, jwt.ExpiredSignatureError):
            raise
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
    if settings.postgres_user == "aml_app":
        vault_app_pw = _secret_store().get("postgres.aml_app_password")
        if vault_app_pw:
            return vault_app_pw

    vault_pw = _secret_store().get("postgres.password")
    if vault_pw:
        return vault_pw

    file_password = _read_secret_file("/var/run/secrets/postgres_password")
    if file_password:
        return file_password

    if settings.postgres_user == "aml_app" and (settings.aml_app_password or os.getenv("AML_APP_PASSWORD")):
        return settings.aml_app_password or os.getenv("AML_APP_PASSWORD", "")

    resolved = settings.postgres_password or os.getenv("POSTGRES_PASSWORD", "")
    if resolved:
        return resolved

    if getattr(settings, "is_hardened", settings.is_production):
        raise RuntimeError("CRITICAL: PostgreSQL password is missing in hardened environment.")
    return "postgrespassword"


def _build_postgres_dsn(user: str, password: str, host: str, port: str, db: str) -> str:
    user_enc = quote_plus(str(user))
    pass_enc = quote_plus(str(password))
    ssl_suffix = "?sslmode=require" if getattr(settings, "enable_tls", False) else ""
    return f"postgresql://{user_enc}:{pass_enc}@{host}:{port}/{db}{ssl_suffix}"


def get_postgres_dsn() -> str:
    """Dynamically builds URL-encoded PostgreSQL primary DSN using credentials from Vault or env."""
    store = _secret_store()
    user = store.get("postgres.user") or settings.postgres_user
    host = store.get("postgres.host") or settings.postgres_host
    port = store.get("postgres.port") or str(settings.postgres_port)
    db = store.get("postgres.db") or settings.postgres_db
    password = get_postgres_password()
    return _build_postgres_dsn(user, password, host, port, db)


def get_postgres_replica_dsn() -> str:
    """Dynamically builds URL-encoded PostgreSQL read-replica DSN using Vault or env credentials."""
    store = _secret_store()
    user = store.get("postgres.user") or settings.postgres_user
    host = store.get("postgres.replica_host") or settings.postgres_replica_host
    port = store.get("postgres.replica_port") or str(settings.postgres_replica_port)
    db = store.get("postgres.db") or settings.postgres_db
    password = get_postgres_password()
    return _build_postgres_dsn(user, password, host, port, db)


def get_outbox_postgres_dsn() -> Optional[str]:
    """
    Returns dedicated least-privilege `aml_outbox_worker` DSN (with scoped BYPASSRLS on
    `transactional_outbox`) from Vault (`postgres.outbox_dsn`) or `OUTBOX_DATABASE_URL`,
    or constructs it from `AML_OUTBOX_WORKER_PASSWORD` if provided. Returns None if not configured.
    """
    store = _secret_store()
    explicit = (store.get("postgres.outbox_dsn") or os.getenv("OUTBOX_DATABASE_URL", "")).strip()
    if explicit:
        return explicit
    worker_pw = (store.get("postgres.outbox_worker_password") or os.getenv("AML_OUTBOX_WORKER_PASSWORD", "")).strip()
    if worker_pw:
        host = store.get("postgres.host") or settings.postgres_host
        port = store.get("postgres.port") or str(settings.postgres_port)
        db = store.get("postgres.db") or settings.postgres_db
        return _build_postgres_dsn("aml_outbox_worker", worker_pw, host, port, db)
    return None


def get_postgres_replica_dsns() -> list[str]:
    """
    Returns one or more PostgreSQL read-replica DSNs.
    When `POSTGRES_REPLICA_HOSTS` is set (comma-separated `host[:port]` entries),
    returns one DSN per replica for round-robin pooling across 2+ streaming standbys.
    """
    store = _secret_store()
    raw_hosts = (
        store.get("postgres.replica_hosts")
        or getattr(settings, "postgres_replica_hosts", "")
        or ""
    ).strip()
    if not raw_hosts:
        return [get_postgres_replica_dsn()]

    user = store.get("postgres.user") or settings.postgres_user
    default_port = str(store.get("postgres.replica_port") or settings.postgres_replica_port)
    db = store.get("postgres.db") or settings.postgres_db
    password = get_postgres_password()

    dsns: list[str] = []
    for entry in raw_hosts.split(","):
        token = entry.strip()
        if not token:
            continue
        if ":" in token:
            host, port = token.rsplit(":", 1)
        else:
            host, port = token, default_port
        dsns.append(_build_postgres_dsn(user, password, host.strip(), port.strip(), db))

    return dsns or [get_postgres_replica_dsn()]


def get_redis_password() -> Optional[str]:
    """Resolves Redis password dynamically from Vault -> mounted file -> env -> settings."""
    vault_pw = _secret_store().get("redis.password")
    if vault_pw:
        return vault_pw
    file_pw = _read_secret_file("/var/run/secrets/redis_password")
    if file_pw:
        return file_pw
    return settings.redis_password or os.getenv("REDIS_PASSWORD") or None
