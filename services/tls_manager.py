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
    If TLS is explicitly enabled (or strict mode is requested), missing certificates raise a RuntimeError
    to prevent unintended unencrypted plaintext fallback.
    """
    ca_path = settings.tls_ca_cert or "/var/run/secrets/tls/ca.crt"
    cert_path = settings.tls_client_cert or "/var/run/secrets/tls/tls.crt"
    key_path = settings.tls_client_key or "/var/run/secrets/tls/tls.key"

    if settings.enable_tls or strict:
        missing = []
        if not os.path.exists(ca_path):
            missing.append(f"CA certificate ({ca_path})")
        if not os.path.exists(cert_path):
            missing.append(f"Client certificate ({cert_path})")
        if not os.path.exists(key_path):
            missing.append(f"Client key ({key_path})")

        if missing:
            raise RuntimeError(
                f"mTLS validation failure: TLS is enabled but required files are missing: {', '.join(missing)}. "
                "Refusing to fall back to plaintext mode."
            )
        logger.info("mTLS configuration validated successfully: internal CA, client cert, and key exist.")


def get_ssl_context(purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH) -> Optional[ssl.SSLContext]:
    """
    Builds a secure SSLContext for encrypted in-transit client connections.
    Returns None if TLS is disabled and no secret certificates are mounted.
    Raises RuntimeError if TLS is required but certificate loading fails.
    """
    ca_path = settings.tls_ca_cert or "/var/run/secrets/tls/ca.crt"
    cert_path = settings.tls_client_cert or "/var/run/secrets/tls/tls.crt"
    key_path = settings.tls_client_key or "/var/run/secrets/tls/tls.key"

    # Check if explicit enable_tls setting is set OR if mounted secrets exist
    tls_active = settings.enable_tls or (os.path.exists(ca_path) and os.path.exists(cert_path))
    if not tls_active:
        return None

    try:
        ctx = ssl.create_default_context(purpose=purpose)

        # Load Custom Internal CA certificate if present
        if os.path.exists(ca_path):
            ctx.load_verify_locations(cafile=ca_path)
            ctx.verify_mode = ssl.CERT_REQUIRED
            logger.info(f"Loaded internal CA root certificate from {ca_path}")
        else:
            if settings.enable_tls:
                raise FileNotFoundError(f"Enabled TLS requires CA cert at {ca_path}")
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        # Load Mutual TLS (mTLS) Client Certificate & Private Key if present
        if os.path.exists(cert_path) and os.path.exists(key_path):
            ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
            logger.info(f"Loaded mTLS client certificate & key from {cert_path}")
        elif settings.enable_tls:
            raise FileNotFoundError(f"Enabled TLS requires client cert and key at {cert_path} / {key_path}")

        return ctx
    except Exception as e:
        logger.error(f"Failed to configure SSLContext: {e}")
        if settings.enable_tls:
            raise RuntimeError(f"Strict mTLS initialization failed: {e}") from e
        return None

