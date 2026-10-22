"""
TLS / mTLS Encryption-in-Transit Manager
==========================================
Provides helper functions to build configured `ssl.SSLContext` objects for
PostgreSQL, Neo4j, Redis, and Elasticsearch connections inside the cluster.

Features:
  - Automatic resolution of mounted mTLS secrets (/var/run/secrets/tls/...).
  - Mutual TLS (mTLS) client certificate authentication.
  - Custom internal Certificate Authority (CA) root validation.
"""

import ssl
import os
import logging
from typing import Optional
from config import settings

logger = logging.getLogger(__name__)


def validate_mtls_configuration(strict: bool = False) -> None:
    """
    Validates mTLS cert paths on application startup.
    If TLS is enabled, strict_mtls is enabled, strict parameter is True, or secret mount directory exists,
    missing certificates raise a RuntimeError to prevent unintended unencrypted plaintext fallback.
    """
    ca_path = settings.tls_ca_cert or "/var/run/secrets/tls/ca.crt"
    cert_path = settings.tls_client_cert or "/var/run/secrets/tls/tls.crt"
    key_path = settings.tls_client_key or "/var/run/secrets/tls/tls.key"

    tls_secret_dir = os.path.dirname(ca_path)
    tls_required = settings.enable_tls or getattr(settings, 'strict_mtls', False) or strict or os.path.exists(tls_secret_dir)

    if tls_required:
        missing = []
        if not os.path.exists(ca_path):
            missing.append(f"CA certificate ({ca_path})")
        if not os.path.exists(cert_path):
            missing.append(f"Client certificate ({cert_path})")
        if not os.path.exists(key_path):
            missing.append(f"Client key ({key_path})")

        if missing:
            raise RuntimeError(
                f"mTLS validation failure: TLS is required/mounted but required files are missing: {', '.join(missing)}. "
                "Refusing to fall back to plaintext mode."
            )
        logger.info("mTLS configuration validated successfully: internal CA, client cert, and key exist.")


def _is_tls_requested(ca_path: str, cert_path: str) -> tuple[bool, bool]:
    tls_secret_dir = os.path.dirname(ca_path)
    tls_required = bool(
        settings.enable_tls
        or getattr(settings, 'strict_mtls', False)
        or os.path.exists(tls_secret_dir)
    )
    secrets_present = os.path.exists(ca_path) and os.path.exists(cert_path)
    tls_active = tls_required or secrets_present
    return tls_required, tls_active


def _load_ca_certs(ctx: ssl.SSLContext, ca_path: str, tls_required: bool) -> None:
    if os.path.exists(ca_path):
        ctx.load_verify_locations(cafile=ca_path)
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.check_hostname = True
        logger.info(f"Loaded internal CA root certificate from {ca_path}")
    elif tls_required:
        raise FileNotFoundError(f"Enabled/required TLS requires CA cert at {ca_path}")
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED


def _load_client_certs(ctx: ssl.SSLContext, cert_path: str, key_path: str, tls_required: bool) -> None:
    if os.path.exists(cert_path) and os.path.exists(key_path):
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
        logger.info(f"Loaded mTLS client certificate & key from {cert_path}")
    elif tls_required:
        raise FileNotFoundError(f"Enabled/required TLS requires client cert and key at {cert_path} / {key_path}")


def get_ssl_context(purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH) -> Optional[ssl.SSLContext]:
    """
    Builds a secure SSLContext for encrypted in-transit client connections.
    Returns None if TLS is disabled and no secret certificates are mounted.
    Raises RuntimeError if TLS is required/active but certificate loading fails.
    """
    ca_path = settings.tls_ca_cert or "/var/run/secrets/tls/ca.crt"
    cert_path = settings.tls_client_cert or "/var/run/secrets/tls/tls.crt"
    key_path = settings.tls_client_key or "/var/run/secrets/tls/tls.key"

    tls_required, tls_active = _is_tls_requested(ca_path, cert_path)
    if not tls_active:
        return None

    try:
        ctx = ssl.create_default_context(purpose=purpose)
        _load_ca_certs(ctx, ca_path, tls_required)
        _load_client_certs(ctx, cert_path, key_path, tls_required)
        return ctx
    except Exception as e:
        logger.exception("Failed to configure SSLContext")
        if tls_active:
            raise RuntimeError(f"Strict mTLS initialization failed: {e}") from e
        return None


