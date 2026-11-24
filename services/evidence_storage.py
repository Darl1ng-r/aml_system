"""
Pluggable Evidence Locker Storage & Malware Scanning Service (P0-3)
===================================================================
Provides regulator-grade evidence storage with:
  1. SHA-256 cryptographic chain-of-custody digests verified on upload & download.
  2. Malware scanning via ClamAV TCP INSTREAM protocol + built-in EICAR test detection.
  3. Pluggable Storage Backends:
     - LocalEvidenceBackend (dev / single-node, tenant-jailed realpath boundary)
     - S3EvidenceBackend (AWS S3 / MinIO / GCS S3-interop using pure-Python SigV4 +
       SSE-KMS encryption + S3 Object Lock COMPLIANCE 5-year BSA WORM retention)
"""

import asyncio
import hashlib
import hmac
import logging
import os
import struct
from datetime import datetime, timedelta, timezone
from typing import Protocol, Tuple
from urllib.parse import quote, urlparse

import httpx
from config import settings

logger = logging.getLogger("aml.evidence_storage")

# Standard AV industry EICAR test string (safe non-malicious detection verifier)
EICAR_SIGNATURE = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def compute_sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


async def scan_bytes_for_malware(data: bytes) -> Tuple[bool, str]:
    """
    Scans uploaded evidence bytes for malware.
    Returns: (is_clean: bool, scan_status_label: str)
    - Always rejects standard EICAR test payloads (zero-dependency security gate).
    - When `settings.clamav_enabled` is True, streams bytes via ClamAV INSTREAM TCP protocol.
    """
    if EICAR_SIGNATURE in data:
        logger.warning("Malware scanner detected EICAR test signature in evidence upload.")
        return False, "INFECTED:Eicar-Signature"

    if not getattr(settings, "clamav_enabled", False):
        return True, "CLEAN"

    host = getattr(settings, "clamav_host", "localhost")
    port = int(getattr(settings, "clamav_port", 3310))
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=3.0)
        try:
            writer.write(b"zINSTREAM\x00")
            chunk_size = 32768
            for idx in range(0, len(data), chunk_size):
                chunk = data[idx : idx + chunk_size]
                writer.write(struct.pack("!I", len(chunk)) + chunk)
            writer.write(struct.pack("!I", 0))
            await writer.drain()
            raw_resp = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            resp_text = raw_resp.decode("utf-8", errors="ignore").strip("\x00\r\n ")
            if resp_text.endswith("OK"):
                return True, "CLEAN_CLAMAV"
            if "FOUND" in resp_text:
                logger.critical(f"ClamAV rejected infected evidence upload: {resp_text}")
                return False, f"INFECTED:{resp_text}"
            logger.warning(f"Unexpected ClamAV response: {resp_text}")
            return False, f"SCAN_ERROR:{resp_text}"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception as exc:
        logger.error(f"ClamAV scan connection failed ({host}:{port}): {exc}")
        if settings.is_production:
            return False, "SCAN_UNAVAILABLE_FAIL_CLOSED"
        return True, "CLEAN_SCAN_SKIPPED_DEV"


class EvidenceStorageBackend(Protocol):
    backend_name: str

    async def put_object(self, tenant_id: str, object_key: str, data: bytes, content_type: str) -> str: ...
    async def get_object(self, tenant_id: str, storage_key: str) -> bytes: ...
    async def delete_object(self, tenant_id: str, storage_key: str) -> None: ...


class LocalEvidenceBackend:
    backend_name = "local"

    def __init__(self, base_dir: str):
        self.base_dir = os.path.realpath(base_dir)
        os.makedirs(self.base_dir, exist_ok=True)

    def _safe_path(self, tenant_id: str, candidate: str) -> str:
        tenant_dir = os.path.realpath(os.path.join(self.base_dir, str(tenant_id)))
        os.makedirs(tenant_dir, exist_ok=True)
        resolved = os.path.realpath(candidate)
        if os.path.commonpath([tenant_dir, resolved]) != tenant_dir:
            raise ValueError("Storage path escapes tenant evidence boundary.")
        return resolved

    async def put_object(self, tenant_id: str, object_key: str, data: bytes, content_type: str) -> str:
        tenant_dir = os.path.realpath(os.path.join(self.base_dir, str(tenant_id)))
        target = self._safe_path(tenant_id, os.path.join(tenant_dir, object_key))

        def _write():
            with open(target, "wb") as fh:
                fh.write(data)

        await asyncio.to_thread(_write)
        return target

    async def get_object(self, tenant_id: str, storage_key: str) -> bytes:
        target = self._safe_path(tenant_id, storage_key)
        if not os.path.exists(target):
            raise FileNotFoundError(f"Evidence file missing: {storage_key}")

        def _read() -> bytes:
            with open(target, "rb") as fh:
                return fh.read()

        return await asyncio.to_thread(_read)

    async def delete_object(self, tenant_id: str, storage_key: str) -> None:
        target = self._safe_path(tenant_id, storage_key)
        if os.path.exists(target):
            await asyncio.to_thread(os.remove, target)


def _sigv4_sign(key: bytes, msg: str) -> bytes:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def _sigv4_signing_key(secret_key: str, date_stamp: str, region: str, service: str = "s3") -> bytes:
    k_date = _sigv4_sign(("AWS4" + secret_key).encode("utf-8"), date_stamp)
    k_region = _sigv4_sign(k_date, region)
    k_service = _sigv4_sign(k_region, service)
    return _sigv4_sign(k_service, "aws4_request")


class S3EvidenceBackend:
    """
    Zero-dependency AWS Signature V4 S3/MinIO/GCS evidence backend with
    SSE-KMS encryption and optional 5-year BSA S3 Object Lock (WORM).
    """

    backend_name = "s3"

    def __init__(
        self,
        bucket: str | None = None,
        endpoint: str | None = None,
        region: str | None = None,
        access_key: str | None = None,
        secret_key: str | None = None,
        kms_key_id: str | None = None,
        worm_enabled: bool | None = None,
    ):
        self.bucket = bucket or getattr(settings, "evidence_s3_bucket", "")
        self.region = region or getattr(settings, "evidence_s3_region", "us-east-1")
        self.endpoint = (endpoint or getattr(settings, "evidence_s3_endpoint", "")).rstrip("/")
        self.access_key = access_key or getattr(settings, "evidence_s3_access_key", "")
        self.secret_key = secret_key or getattr(settings, "evidence_s3_secret_key", "")
        self.kms_key_id = kms_key_id if kms_key_id is not None else getattr(settings, "evidence_kms_key_id", "")
        self.worm_enabled = (
            worm_enabled if worm_enabled is not None else bool(getattr(settings, "evidence_worm_enabled", False))
        )

    def _build_url_and_headers(
        self,
        method: str,
        s3_key: str,
        payload: bytes = b"",
        extra_headers: dict[str, str] | None = None,
    ) -> tuple[str, dict[str, str]]:
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        encoded_key = quote(s3_key.lstrip("/"), safe="/-_.~")

        if self.endpoint:
            base = self.endpoint
            url = f"{base}/{self.bucket}/{encoded_key}"
            parsed = urlparse(url)
            host = parsed.netloc
            canonical_uri = parsed.path
        else:
            host = f"{self.bucket}.s3.{self.region}.amazonaws.com"
            canonical_uri = f"/{encoded_key}"
            url = f"https://{host}{canonical_uri}"

        payload_hash = hashlib.sha256(payload).hexdigest()
        headers: dict[str, str] = {
            "host": host,
            "x-amz-content-sha256": payload_hash,
            "x-amz-date": amz_date,
        }
        if extra_headers:
            for k, v in extra_headers.items():
                headers[k.lower()] = v

        sorted_keys = sorted(headers.keys())
        canonical_headers = "".join(f"{k}:{headers[k].strip()}\n" for k in sorted_keys)
        signed_headers = ";".join(sorted_keys)
        canonical_request = f"{method}\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"

        credential_scope = f"{date_stamp}/{self.region}/s3/aws4_request"
        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )
        signing_key = _sigv4_signing_key(self.secret_key, date_stamp, self.region, "s3")
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        out_headers = dict(headers)
        out_headers["authorization"] = (
            f"AWS4-HMAC-SHA256 Credential={self.access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, Signature={signature}"
        )
        return url, out_headers

    async def put_object(self, tenant_id: str, object_key: str, data: bytes, content_type: str) -> str:
        s3_key = f"evidence/{tenant_id}/{object_key}"
        extra: dict[str, str] = {"content-type": content_type}
        if self.kms_key_id:
            extra["x-amz-server-side-encryption"] = "aws:kms"
            extra["x-amz-server-side-encryption-aws-kms-key-id"] = self.kms_key_id
        else:
            extra["x-amz-server-side-encryption"] = "AES256"

        if self.worm_enabled:
            retain_until = (datetime.now(timezone.utc) + timedelta(days=365 * 5)).strftime("%Y-%m-%dT%H:%M:%SZ")
            extra["x-amz-object-lock-mode"] = "COMPLIANCE"
            extra["x-amz-object-lock-retain-until-date"] = retain_until

        url, headers = self._build_url_and_headers("PUT", s3_key, payload=data, extra_headers=extra)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.put(url, content=data, headers=headers)
            if resp.status_code not in (200, 201):
                raise RuntimeError(f"S3 evidence PUT failed (HTTP {resp.status_code}): {resp.text[:200]}")
        return f"s3://{self.bucket}/{s3_key}"

    async def get_object(self, tenant_id: str, storage_key: str) -> bytes:
        s3_key = storage_key.replace(f"s3://{self.bucket}/", "", 1)
        if not s3_key.startswith(f"evidence/{tenant_id}/"):
            raise ValueError("S3 evidence key escapes tenant namespace.")
        url, headers = self._build_url_and_headers("GET", s3_key)
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                raise FileNotFoundError(f"S3 evidence not found: {storage_key}")
            if resp.status_code != 200:
                raise RuntimeError(f"S3 evidence GET failed (HTTP {resp.status_code})")
            return resp.content

    async def delete_object(self, tenant_id: str, storage_key: str) -> None:
        if self.worm_enabled:
            raise PermissionError("Cannot delete WORM-locked regulatory evidence under 5-year BSA retention.")
        s3_key = storage_key.replace(f"s3://{self.bucket}/", "", 1)
        if not s3_key.startswith(f"evidence/{tenant_id}/"):
            raise ValueError("S3 evidence key escapes tenant namespace.")
        url, headers = self._build_url_and_headers("DELETE", s3_key)
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.delete(url, headers=headers)


DEFAULT_LOCAL_EVIDENCE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "storage", "evidence")
)


def get_evidence_storage_backend(local_base_dir: str | None = None) -> EvidenceStorageBackend:
    mode = str(getattr(settings, "evidence_storage_backend", "local")).lower()
    if mode == "s3" and getattr(settings, "evidence_s3_bucket", ""):
        return S3EvidenceBackend()
    return LocalEvidenceBackend(local_base_dir or DEFAULT_LOCAL_EVIDENCE_DIR)
