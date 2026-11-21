"""
Cryptographically Signed Examiner Packet & Time-Boxed Auditor Room Service (P2-3)
==================================================================================
1. Examiner Packet: Compiles a regulator-ready ZIP archive containing:
     - `manifest.json` (canonical metadata + SHA-256 digests of every included file)
     - `signature.sig` (RS256 signature over `manifest.json` using Sentinel's active RSA key,
       externally verifiable via `/.well-known/jwks.json`)
     - `summary.html` (printable institutional executive dossier, HTML-escaped)
     - `transactions.csv` (CWE-1236 formula-safe CSV export)
     - `audit_trail.json` & `evidence_manifest.json`
2. Time-Boxed Auditor Rooms: Generates revocable, case-allowlisted read-only
   examiner tokens (`aud_<tenant_hex>.<secret>`) stored strictly as SHA-256 digests.
"""

import base64
import csv
import hashlib
import html
import io
import json
import logging
import secrets
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

from services.secrets_manager import get_or_create_rsa_keypair

logger = logging.getLogger("aml.examiner_packet")


def generate_auditor_room_token(tenant_id: str | uuid.UUID) -> Tuple[str, str]:
    """Generates `(raw_token, sha256_token_hash)` for a time-boxed read-only Auditor Room."""
    tenant_hex = uuid.UUID(str(tenant_id)).hex
    secret_part = secrets.token_urlsafe(28)
    raw_token = f"aud_{tenant_hex}.{secret_part}"
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return raw_token, token_hash


def parse_auditor_room_token(raw_token: str) -> Tuple[Optional[str], str]:
    """Extracts `(tenant_id_str, sha256_token_hash)` from an Auditor Room token."""
    if not raw_token or not raw_token.startswith("aud_") or "." not in raw_token:
        return None, ""
    prefix = raw_token[4:].split(".", 1)[0]
    try:
        tenant_id = str(uuid.UUID(hex=prefix))
    except ValueError:
        return None, ""
    token_hash = hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
    return tenant_id, token_hash


def sign_manifest_rs256(manifest_bytes: bytes, private_pem: Optional[bytes] = None) -> str:
    """Signs canonical `manifest.json` bytes with RS256 (PKCS#1 v1.5 + SHA-256) and returns base64 signature."""
    if private_pem is None:
        private_pem, _ = get_or_create_rsa_keypair()
    priv_key = serialization.load_pem_private_key(
        private_pem.encode("utf-8") if isinstance(private_pem, str) else private_pem,
        password=None,
    )
    sig = priv_key.sign(manifest_bytes, padding.PKCS1v15(), hashes.SHA256())
    return base64.b64encode(sig).decode("ascii")


def verify_examiner_packet_signature(manifest_bytes: bytes, signature_b64: str, public_pem: Optional[bytes] = None) -> bool:
    """Cryptographically verifies `signature.sig` against `manifest.json` bytes using the RSA public key."""
    try:
        if public_pem is None:
            _, public_pem = get_or_create_rsa_keypair()
        pub_key = serialization.load_pem_public_key(
            public_pem.encode("utf-8") if isinstance(public_pem, str) else public_pem
        )
        sig_bytes = base64.b64decode(signature_b64.strip())
        pub_key.verify(sig_bytes, manifest_bytes, padding.PKCS1v15(), hashes.SHA256())
        return True
    except Exception:
        return False


def _safe_csv(val: Any) -> str:
    s = "" if val is None else str(val)
    if s and s[0] in ("=", "+", "-", "@", "\t", "\r"):
        return f"'{s}"
    return s


def _build_transactions_csv(txs: List[Dict[str, Any]]) -> bytes:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["transaction_id", "timestamp", "amount", "currency", "amount_base_usd", "status", "channel", "country"])
    for tx in txs:
        writer.writerow([
            _safe_csv(tx.get("id")),
            _safe_csv(tx.get("timestamp")),
            _safe_csv(tx.get("amount")),
            _safe_csv(tx.get("currency")),
            _safe_csv(tx.get("amount_base_usd")),
            _safe_csv(tx.get("status")),
            _safe_csv(tx.get("channel")),
            _safe_csv(tx.get("country")),
        ])
    return buf.getvalue().encode("utf-8")


def _build_summary_html(
    case_data: Dict[str, Any],
    alerts: List[Dict[str, Any]],
    sars: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
    notes: List[Dict[str, Any]],
    generated_at: str,
    generated_by: str,
) -> bytes:
    e = html.escape
    alert_rows = "".join(
        f"<tr><td>{e(str(a.get('id', ''))[:8])}</td><td>{e(str(a.get('rule_name', '')))}</td>"
        f"<td>{e(str(a.get('threat_level', '')))}</td><td>{e(str(a.get('status', '')))}</td></tr>"
        for a in alerts
    ) or "<tr><td colspan='4'>No linked alerts</td></tr>"
    ev_rows = "".join(
        f"<tr><td>{e(str(ev.get('file_name', '')))}</td><td><code>{e(str(ev.get('sha256_digest') or 'N/A'))}</code></td>"
        f"<td>{e(str(ev.get('scan_status') or 'CLEAN'))}</td></tr>"
        for ev in evidence
    ) or "<tr><td colspan='3'>No evidence artifacts attached</td></tr>"

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Examiner Packet — {e(str(case_data.get('case_number', '')))}</title>
<style>
body{{font-family:Inter,system-ui,sans-serif;color:#141517;max-width:960px;margin:24px auto;padding:0 16px;line-height:1.5;}}
h1,h2{{border-bottom:1px solid #d4d3ce;padding-bottom:6px;}}
table{{width:100%;border-collapse:collapse;margin:12px 0 24px 0;font-size:13px;}}
th,td{{border:1px solid #d4d3ce;padding:8px;text-align:left;}}
th{{background:#f5f4f0;}}
code{{font-family:monospace;font-size:12px;}}
</style></head>
<body>
<h1>AML Sentinel — Cryptographically Signed Examiner Dossier</h1>
<p><strong>Case Number:</strong> {e(str(case_data.get('case_number', '')))} |
<strong>Status:</strong> {e(str(case_data.get('status', '')))} |
<strong>Priority:</strong> {e(str(case_data.get('priority', '')))}<br>
<strong>Title:</strong> {e(str(case_data.get('title', '')))}<br>
<strong>Generated At:</strong> {e(generated_at)} by {e(generated_by)}</p>
<h2>Correlated Alerts ({len(alerts)})</h2>
<table><thead><tr><th>Alert ID</th><th>Rule</th><th>Threat</th><th>Status</th></tr></thead><tbody>{alert_rows}</tbody></table>
<h2>Evidence Chain-of-Custody ({len(evidence)})</h2>
<table><thead><tr><th>File</th><th>SHA-256 Digest</th><th>Malware Scan</th></tr></thead><tbody>{ev_rows}</tbody></table>
<h2>Regulatory Filings ({len(sars)}) &amp; Case Notes ({len(notes)})</h2>
<p>Full structured JSON records, CWE-1236-safe transaction CSV, and hash-chained audit logs are bundled in this signed archive. Verify <code>signature.sig</code> against <code>manifest.json</code> via <code>/.well-known/jwks.json</code>.</p>
</body></html>"""
    return doc.encode("utf-8")


async def build_signed_examiner_packet(
    conn: Any,
    tenant_id: str | uuid.UUID,
    case_id: str | uuid.UUID,
    generated_by: str,
) -> Tuple[bytes, Dict[str, Any], str]:
    """
    Compiles a complete, RS256-signed regulator examiner ZIP packet for a case.
    Returns `(zip_bytes, manifest_dict, zip_sha256_hex)`.
    """
    case_uuid = uuid.UUID(str(case_id))
    case_row = await conn.fetchrow("SELECT * FROM cases WHERE id = $1;", case_uuid)
    if not case_row:
        raise KeyError("Case not found.")

    alerts_rows = await conn.fetch(
        """
        SELECT a.id, a.rule_name, a.threat_level, a.ai_risk_score, a.status,
               a.created_at, a.fincen_tracking_id, a.fincen_filing_status, a.transaction_id
        FROM case_alerts ca
        JOIN alerts a ON ca.alert_id = a.id
        WHERE ca.case_id = $1
        ORDER BY a.created_at ASC;
        """,
        case_uuid,
    )
    tx_ids = [r["transaction_id"] for r in (alerts_rows or []) if r.get("transaction_id")]
    tx_rows = []
    if tx_ids:
        tx_rows = await conn.fetch(
            """
            SELECT id, amount, currency, COALESCE(amount_base_usd, amount) AS amount_base_usd,
                   status, timestamp, channel, country
            FROM transactions
            WHERE id = ANY($1::uuid[])
            ORDER BY timestamp ASC;
            """,
            tx_ids,
        )

    sar_rows = await conn.fetch(
        """
        SELECT id, alert_id, status, drafted_by_username, reviewed_by_username,
               fincen_tracking_id, statutory_deadline_at, xsd_validated, created_at
        FROM sar_drafts
        WHERE case_id = $1
        ORDER BY created_at DESC;
        """,
        case_uuid,
    )
    ev_rows = await conn.fetch(
        """
        SELECT id, file_name, mime_type, file_size_bytes, sha256_digest,
               storage_backend, scan_status, uploaded_by_username, uploaded_at
        FROM case_evidence
        WHERE case_id = $1
        ORDER BY uploaded_at ASC;
        """,
        case_uuid,
    )
    note_rows = await conn.fetch(
        """
        SELECT id, author_username, note, created_at
        FROM case_notes
        WHERE case_id = $1
        ORDER BY created_at ASC;
        """,
        case_uuid,
    )
    audit_rows = await conn.fetch(
        """
        SELECT id, action, actor_username, actor_role, resource_type, resource_id, created_at
        FROM audit_log
        WHERE resource_id = $1
        ORDER BY created_at ASC
        LIMIT 200;
        """,
        str(case_uuid),
    )

    def _norm(rows):
        out = []
        for r in (rows or []):
            d = {}
            for k, v in dict(r).items():
                if isinstance(v, (datetime,)):
                    d[k] = v.isoformat()
                elif isinstance(v, uuid.UUID):
                    d[k] = str(v)
                else:
                    d[k] = float(v) if hasattr(v, "__float__") and not isinstance(v, (int, float, bool)) else v
            out.append(d)
        return out

    case_dict = _norm([case_row])[0]
    alerts = _norm(alerts_rows)
    txs = _norm(tx_rows)
    sars = _norm(sar_rows)
    evidence = _norm(ev_rows)
    notes = _norm(note_rows)
    audits = _norm(audit_rows)

    generated_at = datetime.now(timezone.utc).isoformat()
    files_map: Dict[str, bytes] = {
        "summary.html": _build_summary_html(case_dict, alerts, sars, evidence, notes, generated_at, generated_by),
        "transactions.csv": _build_transactions_csv(txs),
        "case_dossier.json": json.dumps(
            {"case": case_dict, "alerts": alerts, "sars": sars, "notes": notes},
            indent=2,
            sort_keys=True,
        ).encode("utf-8"),
        "evidence_manifest.json": json.dumps(evidence, indent=2, sort_keys=True).encode("utf-8"),
        "audit_trail.json": json.dumps(audits, indent=2, sort_keys=True).encode("utf-8"),
    }

    file_digests = {
        fname: hashlib.sha256(content).hexdigest()
        for fname, content in sorted(files_map.items())
    }

    manifest = {
        "packet_version": "1.0",
        "signature_algorithm": "RS256",
        "tenant_id": str(tenant_id),
        "case_id": str(case_uuid),
        "case_number": case_dict.get("case_number"),
        "generated_at": generated_at,
        "generated_by": generated_by,
        "counts": {
            "alerts": len(alerts),
            "transactions": len(txs),
            "sars": len(sars),
            "evidence_artifacts": len(evidence),
            "notes": len(notes),
            "audit_events": len(audits),
        },
        "file_sha256_digests": file_digests,
    }
    manifest_bytes = json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8")
    signature_b64 = sign_manifest_rs256(manifest_bytes)

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for fname, content in files_map.items():
            zf.writestr(fname, content)
        zf.writestr("manifest.json", manifest_bytes)
        zf.writestr("signature.sig", signature_b64.encode("ascii"))

    zip_bytes = zip_buf.getvalue()
    zip_sha256 = hashlib.sha256(zip_bytes).hexdigest()
    return zip_bytes, manifest, zip_sha256
