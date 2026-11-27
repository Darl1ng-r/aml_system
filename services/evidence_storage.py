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
from typing import Any, Protocol, Tuple
from urllib.parse import quote, urlparse

import httpx
from config import settings

logger = logging.getLogger("aml.evidence_storage")

# Pre-signed S3 URL expiry bounds (1 minute min, 15 minutes max)
PRESIGN_MIN_EXPIRY_SECONDS = 60
PRESIGN_MAX_EXPIRY_SECONDS = 900
PRESIGN_DEFAULT_EXPIRY_SECONDS = 300

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
            # P2-03: Bound ClamAV drain so stalled daemon cannot hang upload coroutine indefinitely
            await asyncio.wait_for(writer.drain(), timeout=5.0)
            raw_resp = await asyncio.wait_for(reader.read(1024), timeout=5.0)
            resp_text = raw_resp.decode("utf-8", errors="ignore").strip("\x00\r\n ")
            if resp_text.endswith("OK"):
                return True, "CLEAN_CLAMAV"
            if "FOUND" in resp_text:
                logger.critical("ClamAV rejected infected evidence upload: %s", resp_text)
                return False, "INFECTED"
            logger.warning("Unexpected ClamAV response: %s", resp_text)
            return False, "SCAN_ERROR"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except Exception as exc:
        logger.error("ClamAV scan connection failed (%s:%s): %s", host, port, exc)
        if getattr(settings, "is_hardened", settings.is_production):
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
        if (
            self.endpoint
            and getattr(settings, "is_hardened", settings.is_production)
            and not self.endpoint.lower().startswith("https://")
        ):
            raise ValueError("CRITICAL: Plaintext HTTP S3 evidence endpoint is forbidden in hardened environments.")
        self.access_key = access_key or getattr(settings, "evidence_s3_access_key", "")
        self.secret_key = secret_key or getattr(settings, "evidence_s3_secret_key", "")
        self.kms_key_id = kms_key_id if kms_key_id is not None else getattr(settings, "evidence_kms_key_id", "")
        self.worm_enabled = (
            worm_enabled if worm_enabled is not None else bool(getattr(settings, "evidence_worm_enabled", False))
        )

    def _resolve_object_url_parts(self, s3_key: str) -> tuple[str, str, str]:
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
        return url, host, canonical_uri

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
        url, host, canonical_uri = self._resolve_object_url_parts(s3_key)

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

    def _generate_presigned_url(
        self,
        method: str,
        s3_key: str,
        *,
        expires_in: int = PRESIGN_DEFAULT_EXPIRY_SECONDS,
        signed_headers_map: dict[str, str] | None = None,
        extra_query_params: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Generates a pure-Python AWS Signature V4 query-string pre-signed URL (S3 / MinIO / GCS interop)."""
        if not self.bucket:
            raise ValueError("S3 evidence bucket is not configured.")
        if not self.access_key or not self.secret_key:
            raise ValueError("S3 evidence credentials are required to mint pre-signed URLs.")

        ttl = max(PRESIGN_MIN_EXPIRY_SECONDS, min(PRESIGN_MAX_EXPIRY_SECONDS, int(expires_in)))
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        credential_scope = f"{date_stamp}/{self.region}/s3/aws4_request"

        base_url, host, canonical_uri = self._resolve_object_url_parts(s3_key)
        headers_to_sign: dict[str, str] = {"host": host}
        if signed_headers_map:
            for k, v in signed_headers_map.items():
                headers_to_sign[k.lower().strip()] = str(v).strip()

        sorted_header_keys = sorted(headers_to_sign.keys())
        canonical_headers = "".join(f"{k}:{headers_to_sign[k]}\n" for k in sorted_header_keys)
        signed_headers = ";".join(sorted_header_keys)

        query_params: dict[str, str] = {
            "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
            "X-Amz-Credential": f"{self.access_key}/{credential_scope}",
            "X-Amz-Date": amz_date,
            "X-Amz-Expires": str(ttl),
            "X-Amz-SignedHeaders": signed_headers,
        }
        if extra_query_params:
            for k, v in extra_query_params.items():
                query_params[str(k)] = str(v)

        canonical_querystring = "&".join(
            f"{quote(k, safe='-_.~')}={quote(query_params[k], safe='-_.~')}"
            for k in sorted(query_params.keys())
        )
        canonical_request = (
            f"{method}\n{canonical_uri}\n{canonical_querystring}\n"
            f"{canonical_headers}\n{signed_headers}\nUNSIGNED-PAYLOAD"
        )
        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode('utf-8')).hexdigest()}"
        )
        signing_key = _sigv4_signing_key(self.secret_key, date_stamp, self.region, "s3")
        signature = hmac.new(signing_key, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        signed_url = f"{base_url}?{canonical_querystring}&X-Amz-Signature={signature}"
        return {
            "url": signed_url,
            "method": method,
            "storage_key": f"s3://{self.bucket}/{s3_key}",
            "object_key": s3_key,
            "expires_in": ttl,
            "expires_at": (now + timedelta(seconds=ttl)).isoformat(),
            "required_headers": {k: v for k, v in headers_to_sign.items() if k != "host"},
        }

    def generate_presigned_put_url(
        self,
        tenant_id: str,
        object_key: str,
        content_type: str,
        *,
        expires_in: int = PRESIGN_DEFAULT_EXPIRY_SECONDS,
    ) -> dict[str, Any]:
        """Mints a short-lived SigV4 pre-signed PUT URL scoped strictly to the tenant namespace with SSE enforcement."""
        clean_tenant = str(tenant_id or "").strip()
        clean_obj = str(object_key or "").strip()
        if not clean_tenant or "/" in clean_tenant or "\\" in clean_tenant or ".." in clean_tenant:
            raise ValueError("Invalid tenant_id for pre-signed S3 evidence upload.")
        if not clean_obj or "/" in clean_obj or "\\" in clean_obj or ".." in clean_obj or "\x00" in clean_obj:
            raise ValueError("Invalid object_key for pre-signed S3 evidence upload.")

        s3_key = f"evidence/{clean_tenant}/{clean_obj}"
        signed_headers_map: dict[str, str] = {"content-type": content_type}
        if self.kms_key_id:
            signed_headers_map["x-amz-server-side-encryption"] = "aws:kms"
            signed_headers_map["x-amz-server-side-encryption-aws-kms-key-id"] = self.kms_key_id
        else:
            signed_headers_map["x-amz-server-side-encryption"] = "AES256"

        return self._generate_presigned_url(
            "PUT",
            s3_key,
            expires_in=expires_in,
            signed_headers_map=signed_headers_map,
        )

    def generate_presigned_get_url(
        self,
        tenant_id: str,
        storage_key: str,
        *,
        expires_in: int = PRESIGN_DEFAULT_EXPIRY_SECONDS,
        download_filename: str | None = None,
    ) -> dict[str, Any]:
        """Mints a short-lived SigV4 pre-signed GET URL after verifying strict tenant & bucket boundaries."""
        clean_tenant = str(tenant_id or "").strip()
        if not clean_tenant:
            raise ValueError("Invalid tenant_id for pre-signed S3 evidence download.")

        prefix = f"s3://{self.bucket}/"
        if str(storage_key).startswith("s3://") and not str(storage_key).startswith(prefix):
            raise ValueError("S3 evidence key targets a different bucket.")
        s3_key = str(storage_key).replace(prefix, "", 1)
        if not s3_key.startswith(f"evidence/{clean_tenant}/") or ".." in s3_key or "\x00" in s3_key:
            raise ValueError("S3 evidence key escapes tenant namespace.")

        extra_query: dict[str, str] | None = None
        if download_filename:
            safe_name = os.path.basename(download_filename).replace('"', "").replace("\r", "").replace("\n", "")
            if safe_name:
                extra_query = {"response-content-disposition": f'attachment; filename="{safe_name}"'}

        return self._generate_presigned_url(
            "GET",
            s3_key,
            expires_in=expires_in,
            extra_query_params=extra_query,
        )

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
        from services.http_client import request_with_resilience
        resp = await request_with_resilience(
            "PUT",
            url,
            target="s3_evidence",
            timeout=httpx.Timeout(connect=3.0, read=15.0, write=15.0, pool=2.0),
            follow_redirects=False,
            retries=2,
            content=data,
            headers=headers,
        )
        if resp.status_code not in (200, 201):
            logger.error("S3 evidence PUT failed (HTTP %s): %s", resp.status_code, resp.text[:200])
            raise RuntimeError(f"S3 evidence PUT failed (HTTP {resp.status_code})")
        return f"s3://{self.bucket}/{s3_key}"

    async def get_object(self, tenant_id: str, storage_key: str) -> bytes:
        s3_key = storage_key.replace(f"s3://{self.bucket}/", "", 1)
        if not s3_key.startswith(f"evidence/{tenant_id}/"):
            raise ValueError("S3 evidence key escapes tenant namespace.")
        url, headers = self._build_url_and_headers("GET", s3_key)
        from services.http_client import request_with_resilience
        resp = await request_with_resilience(
            "GET",
            url,
            target="s3_evidence",
            timeout=httpx.Timeout(connect=3.0, read=15.0, write=5.0, pool=2.0),
            follow_redirects=False,
            retries=2,
            headers=headers,
        )
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
        from services.http_client import request_with_resilience
        resp = await request_with_resilience(
            "DELETE",
            url,
            target="s3_evidence",
            timeout=httpx.Timeout(connect=3.0, read=10.0, write=5.0, pool=2.0),
            follow_redirects=False,
            retries=2,
            headers=headers,
        )
        if resp.status_code not in (200, 202, 204, 404):
            raise RuntimeError(f"S3 evidence DELETE failed (HTTP {resp.status_code})")


DEFAULT_LOCAL_EVIDENCE_DIR = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "storage", "evidence")
)


def get_evidence_storage_backend(local_base_dir: str | None = None) -> EvidenceStorageBackend:
    mode = str(getattr(settings, "evidence_storage_backend", "local")).strip().lower()
    bucket = str(getattr(settings, "evidence_s3_bucket", "") or "").strip()
    if mode == "s3" and bucket:
        return S3EvidenceBackend()
    if getattr(settings, "is_hardened", settings.is_production):
        raise RuntimeError(
            "CRITICAL: Local pod filesystem evidence storage is forbidden in hardened environments "
            "(production/staging). Configure EVIDENCE_STORAGE_BACKEND=s3 and EVIDENCE_S3_BUCKET "
            "to keep the application tier 100% stateless."
        )
    return LocalEvidenceBackend(local_base_dir or DEFAULT_LOCAL_EVIDENCE_DIR)
