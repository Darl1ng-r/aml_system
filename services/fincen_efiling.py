"""
FinCEN BSA E-Filing System Gateway Service
============================================
Hardened integration with FinCEN BSA E-Filing API & SDTM SFTP gateway:
  - Dynamic Vault/env resolution on every call (no import-time SecretStore race)
  - Strict environment isolation: live REST/SFTP forbidden outside production;
    silent sandbox mode forbidden inside production (fixes P0-10)
  - Non-blocking SFTP via asyncio.to_thread + SSHClient + strict known_hosts
    RejectPolicy + connect/banner/auth timeouts
  - Pooled httpx client with split timeouts, follow_redirects=False, and circuit breaker
  - Scrubs raw upstream error response text from client-facing confirmation messages
"""

import asyncio
import hashlib
import hmac
import io
import logging
import os
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    import httpx
except ImportError:
    httpx = None

from config import settings
from services.http_client import CircuitOpenError, request_with_resilience

logger = logging.getLogger(__name__)


def _get_fincen_secret(field: str, env_var: str, default: str = "") -> str:
    """Resolve a FinCEN credential dynamically: Vault SecretStore -> env var -> default."""
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
        self._override_api_url: Optional[str] = None
        self._override_tin: Optional[str] = None
        self._override_api_key: Optional[str] = None
        self._override_sandbox: Optional[bool] = None

    @property
    def api_url(self) -> str:
        if self._override_api_url is not None:
            return self._override_api_url
        return _get_fincen_secret(
            "efiling_url",
            "FINCEN_EFILING_URL",
            "https://bsaefiling.fincen.treas.gov/api/v2/sar/submit",
        )

    @api_url.setter
    def api_url(self, value: str) -> None:
        self._override_api_url = value

    @property
    def tin(self) -> str:
        if self._override_tin is not None:
            return self._override_tin
        return _get_fincen_secret("transmitter_tin", "FINCEN_TRANSMITTER_TIN", "999887766")

    @tin.setter
    def tin(self, value: str) -> None:
        self._override_tin = value

    @property
    def api_key(self) -> str:
        if self._override_api_key is not None:
            return self._override_api_key
        return _get_fincen_secret("api_key", "FINCEN_API_KEY", "")

    @api_key.setter
    def api_key(self, value: str) -> None:
        self._override_api_key = value

    @property
    def sandbox(self) -> bool:
        if self._override_sandbox is not None:
            return self._override_sandbox
        env_val = os.getenv("FINCEN_SANDBOX_MODE")
        if env_val is not None:
            return env_val.strip().lower() == "true"
        return bool(getattr(settings, "fincen_sandbox_mode", True))

    @sandbox.setter
    def sandbox(self, value: bool) -> None:
        self._override_sandbox = bool(value)

    def _resolve_transport_mode(self) -> str:
        """
        Determines and validates active transport mode (`sandbox` | `rest` | `sftp`):
          - Outside production (`not settings.is_production`): live `rest`/`sftp` is strictly forbidden.
          - Inside production (`settings.is_production`): `sandbox` mode is strictly forbidden.
        """
        transport = str(getattr(settings, "fincen_transport", "sandbox")).strip().lower()
        if transport not in {"sandbox", "rest", "sftp"}:
            raise RuntimeError(f"Unsupported FINCEN_TRANSPORT value '{transport}'.")

        is_prod = bool(settings.is_production)
        if not is_prod and (transport != "sandbox" or not self.sandbox):
            raise RuntimeError(
                "CRITICAL (P0-10): Live FinCEN submission (REST/SFTP) is strictly forbidden outside production."
            )
        if is_prod and (transport == "sandbox" or self.sandbox):
            raise RuntimeError(
                "CRITICAL (P0-10): Production environment must NOT file SARs to FinCEN sandbox. "
                "Configure FINCEN_TRANSPORT=rest|sftp and FINCEN_SANDBOX_MODE=false."
            )
        return transport

    def generate_signature(self, payload_bytes: bytes) -> str:
        """Computes HMAC-SHA256 signature for electronic transmission validation."""
        file_password = _get_fincen_secret("file_password", "FINCEN_FILE_PASSWORD", "")
        secret = file_password.encode("utf-8")
        return hmac.new(secret, payload_bytes, digestmod=hashlib.sha256).hexdigest()

    def validate_sar_xml(self, xml_str: str, fiu_format: str | None = None) -> bool:
        """Validates XML structural & regulatory conformance (XXE-safe FinCEN & goAML 5.0)."""
        from services.sar_validator import validate_regulatory_xml
        ok, errors = validate_regulatory_xml(xml_str, fiu_format=fiu_format)
        if not ok:
            logger.warning("Regulatory SAR XML validation failed: %s", errors)
        return ok

    @staticmethod
    def _sftp_upload_sync(
        host: str,
        port: int,
        username: str,
        password: str,
        remote_path: str,
        known_hosts_path: str,
        payload_bytes: bytes,
    ) -> None:
        try:
            import paramiko  # type: ignore
        except ImportError as exc:
            raise RuntimeError(
                "SFTP FinCEN transport requires 'paramiko' package installed in production."
            ) from exc

        if not known_hosts_path or not os.path.exists(known_hosts_path):
            raise RuntimeError(
                f"FinCEN SFTP requires a pinned SSH known_hosts file at '{known_hosts_path}' "
                "to prevent MITM attacks on regulatory filings."
            )

        ssh = paramiko.SSHClient()
        ssh.load_host_keys(known_hosts_path)
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            ssh.connect(
                hostname=host,
                port=port,
                username=username,
                password=password,
                timeout=10.0,
                banner_timeout=10.0,
                auth_timeout=10.0,
                allow_agent=False,
                look_for_keys=False,
            )
            sftp = ssh.open_sftp()
            try:
                sftp.putfo(io.BytesIO(payload_bytes), remote_path)
            finally:
                sftp.close()
        finally:
            ssh.close()

    async def _submit_via_sftp(self, payload_bytes: bytes, tracking_id: str) -> Dict[str, Any]:
        """Transmits signed BSABatch XML over verified SFTP off the asyncio event loop."""
        host = getattr(settings, "fincen_sftp_host", "") or os.getenv("FINCEN_SFTP_HOST", "")
        port = int(getattr(settings, "fincen_sftp_port", 22) or 22)
        username = getattr(settings, "fincen_sftp_username", "") or os.getenv("FINCEN_SFTP_USERNAME", "")
        remote_dir = getattr(settings, "fincen_sftp_remote_dir", "/incoming/bsa")
        known_hosts = getattr(settings, "fincen_known_hosts_path", "") or os.getenv(
            "FINCEN_KNOWN_HOSTS_PATH", "/etc/aml/fincen_known_hosts"
        )
        remote_path = f"{remote_dir.rstrip('/')}/{tracking_id}.xml"
        password = _get_fincen_secret("sftp_password", "FINCEN_SFTP_PASSWORD", "")

        await asyncio.to_thread(
            self._sftp_upload_sync,
            host,
            port,
            username,
            password,
            remote_path,
            known_hosts,
            payload_bytes,
        )

        return {
            "status": "ACKNOWLEDGED",
            "fincen_tracking_id": tracking_id,
            "fincen_ack_code": "SFTP_UPLOADED_200",
            "submitted_at": datetime.now(timezone.utc).isoformat(),
            "fincen_confirmation_message": "BSABatch XML uploaded via verified SFTP.",
            "transport": "SFTP_BATCH",
            "sandbox": False,
        }

    async def submit_sar(self, sar_xml: str, alert_id: str, fiu_format: str | None = None) -> Dict[str, Any]:
        """Submits a Suspicious Activity Report electronically to FinCEN / FIU."""
        from services.sar_validator import validate_sar_xml_async
        is_valid, val_errors = await validate_sar_xml_async(sar_xml, fiu_format=fiu_format)
        if not is_valid:
            raise ValueError(f"Invalid FinCEN SAR XML schema structure: {'; '.join(val_errors)}")

        transport_mode = self._resolve_transport_mode()

        payload_bytes = sar_xml.encode("utf-8")
        signature = self.generate_signature(payload_bytes)
        tracking_id = f"BSA-{datetime.now(timezone.utc).strftime('%Y')}-{uuid.uuid4().hex[:10].upper()}"

        if transport_mode == "sandbox":
            logger.info("[FinCEN Sandbox] Simulating electronic SAR filing for alert %s | Tracking ID: %s", alert_id, tracking_id)
            return {
                "status": "ACKNOWLEDGED",
                "fincen_tracking_id": tracking_id,
                "fincen_ack_code": "ACK_SUCCESS_200",
                "submitted_at": datetime.now(timezone.utc).isoformat(),
                "fincen_confirmation_message": "Report successfully validated and ingested by FinCEN BSA E-Filing System (Sandbox Verified).",
                "transport": "SANDBOX",
                "xsd_validated": True,
                "sandbox": True,
            }

        if transport_mode == "sftp":
            return await self._submit_via_sftp(payload_bytes, tracking_id)

        if httpx is None:
            raise RuntimeError("httpx module is required for production FinCEN HTTP calls.")

        headers = {
            "Content-Type": "application/xml",
            "X-FinCEN-Transmitter-TIN": self.tin,
            "X-FinCEN-API-Key": self.api_key,
            "X-FinCEN-Signature": signature,
            "X-FinCEN-Tracking-ID": tracking_id,
        }

        try:
            response = await request_with_resilience(
                "POST",
                self.api_url,
                target="fincen_efiling",
                timeout=httpx.Timeout(connect=3.0, read=25.0, write=10.0, pool=2.0),
                follow_redirects=False,
                retries=0,  # Never auto-retry non-idempotent live regulatory filings
                content=payload_bytes,
                headers=headers,
            )

            if response.status_code in (200, 201, 202):
                return {
                    "status": "ACKNOWLEDGED",
                    "fincen_tracking_id": tracking_id,
                    "fincen_ack_code": f"ACK_{response.status_code}",
                    "submitted_at": datetime.now(timezone.utc).isoformat(),
                    "fincen_confirmation_message": "Report successfully filed to FinCEN BSA E-Filing system.",
                    "transport": "REST",
                    "sandbox": False,
                }
            logger.error("FinCEN Gateway rejected submission: HTTP %s - %s", response.status_code, response.text[:500])
            return {
                "status": "REJECTED",
                "fincen_tracking_id": tracking_id,
                "fincen_ack_code": f"NACK_{response.status_code}",
                "submitted_at": datetime.now(timezone.utc).isoformat(),
                "fincen_confirmation_message": f"FinCEN gateway rejected filing (HTTP {response.status_code}).",
                "transport": "REST",
                "sandbox": False,
            }
        except CircuitOpenError as exc:
            logger.error("FinCEN circuit breaker open: %s", exc)
            raise RuntimeError("FinCEN gateway temporarily unavailable (circuit open).") from exc
        except Exception as e:
            logger.exception("FinCEN HTTP connection failed: %s", e)
            raise RuntimeError("FinCEN gateway connection error.") from e

    async def generate_sar_narrative(
        self,
        alert_id: str,
        tenant_id: Optional[str] = None,
        conn=None,
        analyst_id: Optional[str] = None,
        justification_notes: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Generates standardized 5-part FinCEN SAR narrative for the alert."""
        from services.sar_narrative import generate_sar_narrative
        return await generate_sar_narrative(
            alert_id=alert_id,
            tenant_id=tenant_id,
            conn=conn,
            analyst_id=analyst_id,
            justification_notes=justification_notes,
        )


fincen_client = FinCENEfilingClient()


def get_fincen_client() -> FinCENEfilingClient:
    return fincen_client
