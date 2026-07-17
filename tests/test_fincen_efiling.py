import pytest
import hashlib
import hmac
from services.fincen_efiling import FinCENEfilingClient


def test_fincen_signature_rfc4231_vector():
    """Verify HMAC-SHA256 signature generation against RFC 4231 Test Case 2 known vector.

    Credentials are now resolved via _get_fincen_secret (Vault -> env -> default).
    We patch _get_fincen_secret to inject the RFC test vector key directly.
    """
    # RFC 4231 Test Case 2 (HMAC-SHA-256)
    key_str = "Jefe"
    data = b"what do ya want for nothing?"
    expected_hex = "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"

    with pytest.MonkeyPatch.context() as mp:
        # Patch the resolver so it returns our test key for the file_password field
        mp.setattr(
            "services.fincen_efiling._get_fincen_secret",
            lambda field, env_var, default="": key_str if field == "file_password" else default
        )
        client = FinCENEfilingClient()
        calculated_hex = client.generate_signature(data)
        assert calculated_hex == expected_hex


def test_fincen_generate_signature_returns_valid_sha256_hex():
    """Verify generate_signature outputs valid 64-character hex string."""
    client = FinCENEfilingClient()
    payload = b"<SuspiciousActivityReport><Test>123</Test></SuspiciousActivityReport>"

    signature = client.generate_signature(payload)

    assert isinstance(signature, str)
    assert len(signature) == 64
    assert all(c in "0123456789abcdef" for c in signature)


def test_fincen_validate_sar_xml():
    """Verify XML structural validation helper."""
    client = FinCENEfilingClient()

    valid_xml = "<SuspiciousActivityReport><Header><ReportID>123</ReportID></Header></SuspiciousActivityReport>"
    invalid_xml = "<InvalidRoot><Header></Header></InvalidRoot>"
    malformed_xml = "<SuspiciousActivityReport><UnclosedTag>"

    assert client.validate_sar_xml(valid_xml) is True
    assert client.validate_sar_xml(invalid_xml) is False
    assert client.validate_sar_xml(malformed_xml) is False


@pytest.mark.anyio
async def test_fincen_submit_sar_sandbox():
    """Verify sandbox submission returns ACKNOWLEDGED status with valid tracking ID."""
    client = FinCENEfilingClient()
    valid_xml = "<SuspiciousActivityReport><Header><ReportID>BSA-999</ReportID></Header></SuspiciousActivityReport>"

    result = await client.submit_sar(valid_xml, alert_id="00000000-0000-0000-0000-000000000001")

    assert result["status"] == "ACKNOWLEDGED"
    assert result["sandbox"] is True
    assert result["fincen_tracking_id"].startswith("BSA-")
    assert result["fincen_ack_code"] == "ACK_SUCCESS_200"
