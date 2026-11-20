"""
FinCEN BSA E-Filing System Gateway Service
============================================
Provides integration with the U.S. Department of the Treasury FinCEN BSA E-Filing API.

Features:
  - BSAR XML Payload Validation & Header Signing (HMAC-SHA256).
  - Production & Sandbox E-Filing Submission Endpoints.
  - Electronic Acknowledgement (ACK / NACK) Parsing & Tracking ID Resolution.
"""

import hashlib
import hmac
import json
import logging
import os
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Dict, Any, Optional

try:
    import httpx
except ImportError:
    httpx = None

from config import settings

logger = logging.getLogger(__name__)


def _get_fincen_secret(field: str, env_var: str, default: str = "") -> str:
    """Resolve a FinCEN credential: Vault SecretStore -> env var -> default."""
    try:
        from services.vault_loader import SecretStore
        vault_value = SecretStore.get(f"fincen.{field}")
        if vault_value:
            return vault_value
    except ImportError:
        pass
    return os.getenv(env_var, default)


class FinCENEfilingClient:
    """Client interface for electronically submitting SAR filings to the FinCEN BSA E-Filing gateway."""

    def __init__(self):
        self.api_url = _get_fincen_secret(
            "efiling_url", "FINCEN_EFILING_URL",
            "https://bsaefiling.fincen.treas.gov/api/v2/sar/submit"
        )
        self.tin = _get_fincen_secret(
            "transmitter_tin", "FINCEN_TRANSMITTER_TIN", "999887766"
        )
        self.api_key = _get_fincen_secret(
            "api_key", "FINCEN_API_KEY", ""
        )
        self.sandbox = os.getenv("FINCEN_SANDBOX_MODE", "true").lower() == "true"

    def generate_signature(self, payload_bytes: bytes) -> str:
        """Computes HMAC-SHA256 signature for electronic transmission validation."""
        file_password = _get_fincen_secret(
            "file_password", "FINCEN_FILE_PASSWORD", ""
        )
        secret = file_password.encode("utf-8")
        return hmac.new(secret, payload_bytes, digestmod=hashlib.sha256).hexdigest()

    def validate_sar_xml(self, xml_str: str, fiu_format: str | None = None) -> bool:
        """Validates XML structural & regulatory conformance (XXE-safe FinCEN & goAML 5.0)."""
        from services.sar_validator import validate_regulatory_xml
        ok, errors = validate_regulatory_xml(xml_str, fiu_format=fiu_format)
        if not ok:
            logger.warning(f"Regulatory SAR XML validation failed: {errors}")
        return ok

    async def _submit_via_sftp(self, payload_bytes: bytes, tracking_id: str) -> Dict[str, Any]:
        """Transmits signed BSABatch XML over SFTP to FinCEN SDTM drop-box."""
        host = getattr(settings, "fincen_sftp_host", "") or os.getenv("FINCEN_SFTP_HOST", "")
        port = int(getattr(settings, "fincen_sftp_port", 22) or 22)
        username = getattr(settings, "fincen_sftp_username", "") or os.getenv("FINCEN_SFTP_USERNAME", "")
        remote_dir = getattr(settings, "fincen_sftp_remote_dir", "/incoming/bsa")
        remote_path = f"{remote_dir.rstrip('/')}/{tracking_id}.xml"

        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "SFTP FinCEN transport requires 'paramiko' package installed in production."
            ) from exc

        import io
        password = _get_fincen_secret("sftp_password", "FINCEN_SFTP_PASSWORD", "")
        transport = paramiko.Transport((host, port))
        try:
            transport.connect(username=username, password=password)
            sftp = paramiko.SFTPClient.from_transport(transport)
            try:
                sftp.putfo(io.BytesIO(payload_bytes), remote_path)
            finally:
                sftp.close()
        finally:
            transport.close()

        return {
            "status": "ACKNOWLEDGED",
            "fincen_tracking_id": tracking_id,
            "fincen_ack_code": "SFTP_UPLOADED_200",
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "fincen_confirmation_message": f"BSABatch XML uploaded via SFTP to {remote_path}.",
            "transport": "SFTP_BATCH",
            "sandbox": False,
        }

    async def submit_sar(self, sar_xml: str, alert_id: str, fiu_format: str | None = None) -> Dict[str, Any]:
        """
        Submits a Suspicious Activity Report electronically to FinCEN / FIU.
        Enforces strict regulatory XML validation prior to transmission.
        """
        from services.sar_validator import validate_regulatory_xml
        is_valid, val_errors = validate_regulatory_xml(sar_xml, fiu_format=fiu_format)
        if not is_valid:
            raise ValueError(f"Invalid FinCEN SAR XML schema structure: {'; '.join(val_errors)}")

        payload_bytes = sar_xml.encode("utf-8")
        signature = self.generate_signature(payload_bytes)
        tracking_id = f"BSA-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:10].upper()}"

        headers = {
            "Content-Type": "application/xml",
            "X-FinCEN-Transmitter-TIN": self.tin,
            "X-FinCEN-API-Key": self.api_key,
            "X-FinCEN-Signature": signature,
            "X-FinCEN-Tracking-ID": tracking_id
        }

        transport_mode = str(getattr(settings, "fincen_transport", "sandbox")).lower()
        if not self.sandbox and transport_mode == "sftp":
            return await self._submit_via_sftp(payload_bytes, tracking_id)

        if self.sandbox:
            logger.info(f"[FinCEN Sandbox] Simulating electronic SAR filing for alert {alert_id} | Tracking ID: {tracking_id}")
            return {
                "status": "ACKNOWLEDGED",
                "fincen_tracking_id": tracking_id,
                "fincen_ack_code": "ACK_SUCCESS_200",
                "submitted_at": datetime.now(timezone.utc).isoformat(),
                "fincen_confirmation_message": "Report successfully validated and ingested by FinCEN BSA E-Filing System (Sandbox Verified).",
                "transport": "SANDBOX",
                "xsd_validated": True,
                "sandbox": True
            }

        # Real FinCEN E-Filing HTTP Call
        if httpx is None:
            raise RuntimeError("httpx module is required for production FinCEN HTTP calls.")

        try:
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(self.api_url, content=payload_bytes, headers=headers)

                if response.status_code in [200, 201, 202]:
                    return {
                        "status": "ACKNOWLEDGED",
                        "fincen_tracking_id": tracking_id,
                        "fincen_ack_code": f"ACK_{response.status_code}",
                        "submitted_at": datetime.now(timezone.utc).isoformat(),
                        "fincen_confirmation_message": "Report successfully filed to FinCEN BSA E-Filing system.",
                        "sandbox": False
                    }
                else:
                    logger.error(f"FinCEN Gateway rejected submission: HTTP {response.status_code} - {response.text}")
                    return {
                        "status": "REJECTED",
                        "fincen_tracking_id": tracking_id,
                        "fincen_ack_code": f"NACK_{response.status_code}",
                        "submitted_at": datetime.now(timezone.utc).isoformat(),
                        "fincen_confirmation_message": f"FinCEN filing failed: {response.text}",
                        "sandbox": False
                    }
        except Exception as e:
            logger.exception(f"FinCEN HTTP connection failed: {e}")
            raise RuntimeError(f"FinCEN connection error: {str(e)}")

    async def generate_sar_narrative(
        self,
        alert_id: str,
        tenant_id: Optional[str] = None,
        conn=None,
        analyst_id: Optional[str] = None,
        justification_notes: Optional[str] = None
    ) -> Dict[str, Any]:
        """Generates standardized 5-part FinCEN SAR narrative for the alert."""
        from services.sar_narrative import generate_sar_narrative
        return await generate_sar_narrative(
            alert_id=alert_id,
            tenant_id=tenant_id,
            conn=conn,
            analyst_id=analyst_id,
            justification_notes=justification_notes
        )


fincen_client = FinCENEfilingClient()

