import pytest
import os
import ssl
from unittest.mock import patch, MagicMock
from config import settings
from services.tls_manager import validate_mtls_configuration, get_ssl_context


def test_validate_mtls_configuration_disabled():
    """When TLS is disabled and no secret dir exists, validation passes silently."""
    with patch.object(settings, "enable_tls", False), \
         patch.object(settings, "strict_mtls", False), \
         patch("os.path.exists", return_value=False):
        # Should not raise any exception
        validate_mtls_configuration()


def test_validate_mtls_configuration_enabled_missing_certs():
    """When TLS is enabled but certificate files are missing, raise RuntimeError."""
    with patch.object(settings, "enable_tls", True), \
         patch.object(settings, "strict_mtls", False), \
         patch("os.path.exists", return_value=False):
        with pytest.raises(RuntimeError, match="mTLS validation failure"):
            validate_mtls_configuration()


def test_validate_mtls_configuration_strict_missing_certs():
    """When strict mode is passed, missing certificate files raise RuntimeError."""
    with patch.object(settings, "enable_tls", False), \
         patch.object(settings, "strict_mtls", False), \
         patch("os.path.exists", return_value=False):
        with pytest.raises(RuntimeError, match="mTLS validation failure"):
            validate_mtls_configuration(strict=True)


def test_validate_mtls_configuration_mounted_dir_missing_certs():
    """When secret directory exists (e.g. /var/run/secrets/tls), missing files raise RuntimeError."""
    def exists_side_effect(path):
        # Mount dir exists, but individual cert files do not
        if path == "/var/run/secrets/tls":
            return True
        return False

    with patch.object(settings, "enable_tls", False), \
         patch.object(settings, "strict_mtls", False), \
         patch("os.path.exists", side_effect=exists_side_effect):
        with pytest.raises(RuntimeError, match="mTLS validation failure"):
            validate_mtls_configuration()


def test_validate_mtls_configuration_success():
    """When all certificate files exist, validation succeeds."""
    with patch.object(settings, "enable_tls", True), \
         patch("os.path.exists", return_value=True):
        validate_mtls_configuration()


def test_get_ssl_context_disabled():
    """When TLS is disabled and no certs exist, get_ssl_context returns None."""
    with patch.object(settings, "enable_tls", False), \
         patch.object(settings, "strict_mtls", False), \
         patch("os.path.exists", return_value=False):
        ctx = get_ssl_context()
        assert ctx is None


def test_get_ssl_context_enabled_missing_certs_raises():
    """When TLS is required/active but cert loading fails, raise RuntimeError refusing plaintext fallback."""
    with patch.object(settings, "enable_tls", True), \
         patch("os.path.exists", return_value=False):
        with pytest.raises(RuntimeError, match="Strict mTLS initialization failed"):
            get_ssl_context()


@patch("ssl.create_default_context")
def test_get_ssl_context_success(mock_create_ctx):
    """When TLS is enabled and certs exist, returns populated SSLContext."""
    mock_ctx = MagicMock()
    mock_create_ctx.return_value = mock_ctx

    with patch.object(settings, "enable_tls", True), \
         patch("os.path.exists", return_value=True):
        ctx = get_ssl_context()
        assert ctx == mock_ctx
        mock_ctx.load_verify_locations.assert_called_once()
        mock_ctx.load_cert_chain.assert_called_once()
