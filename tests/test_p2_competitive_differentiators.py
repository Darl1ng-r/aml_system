"""
P2 Competitive Differentiators — Verification Test Suite
========================================================
Validates all 5 P2 deliverables:
  P2-1: External Customer/RM RFI Portal (Tokenized Upload + SLA Pause + Zero Tipping-Off + Malware Scan)
  P2-2: Grounded SAR Narrative Co-Pilot (PII Tokenization + Evidence Auto-Citation + Numeric Hallucination Guard)
  P2-3: RS256-Signed Examiner Packet ZIP (Tamper-Evident Verification) + Time-Boxed Auditor Room Scope/Revocation
  P2-4: Multi-Layer Corporate UBO Ownership Tree (>25% Indirect & Split-Stake Aggregation + Cycle Guard) & MDM Links
  P2-5: Live Adverse Media NLP Connector (GDELT 2.0 + Sentence-Window Entity Disambiguation & Namesake Suppression)
"""

import io
import json
import uuid
import zipfile
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from httpx import ASGITransport

from main import app
from services.adverse_media import disambiguate_adverse_hit, screen_live_adverse_media
from services.auth import create_access_token
from services.evidence_storage import EICAR_SIGNATURE
from services.examiner_packet import (
    generate_auditor_room_token,
    verify_examiner_packet_signature,
)
from services.rfi import generate_rfi_token, parse_rfi_token
from services.sar_narrative import (
    detokenize_pii_from_llm,
    tokenize_pii_for_llm,
    verify_grounded_monetary_figures,
)
from services.ubo_resolver import resolve_ubo_ownership_tree

TENANT_ID = "00000000-0000-0000-0000-000000000001"


def _make_token(role: str = "MLRO", username: str = "elena.mlro") -> str:
    return create_access_token({
        "sub": str(uuid.uuid4()),
        "id": str(uuid.uuid4()),
        "username": username,
        "role": role,
        "tenant_id": TENANT_ID,
    })


# ── P2-1: External RFI Portal, SLA Pause, Zero Tipping-Off & Malware Scan ──────
@pytest.mark.anyio
async def test_p2_1_rfi_lifecycle_zero_tipping_off_malware_reject_and_sla_resume():
    raw_token, token_hash = generate_rfi_token(TENANT_ID)
    parsed_tid, parsed_hash = parse_rfi_token(raw_token)
    assert parsed_tid == TENANT_ID
    assert parsed_hash == token_hash

    case_id = uuid.uuid4()
    rfi_id = uuid.uuid4()
    expires = datetime.now(timezone.utc) + timedelta(hours=48)

    # 1. Public GET returns strictly customer-safe prompt (no case_id, risk_score, rule_name)
    mock_read_conn = AsyncMock()
    mock_read_conn.fetchrow = AsyncMock(return_value={
        "status": "OPEN",
        "recipient_role": "CUSTOMER",
        "prompt_message": "Please upload source of funds statement.",
        "requested_docs": ["Source of Funds Statement"],
        "expires_at": expires,
        "submitted_at": None,
    })
    read_ctx = AsyncMock()
    read_ctx.__aenter__.return_value = mock_read_conn
    read_ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("routers.rfi.get_async_db_read_conn", return_value=read_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get(f"/api/v1/rfi/public/{raw_token}")
            assert res.status_code == 200
            body = res.json()
            assert body["prompt_message"] == "Please upload source of funds statement."
            assert "case_id" not in body
            assert "risk_score" not in body
            assert "rule_name" not in body

    # 2. Public POST rejects EICAR malware with 422
    mock_conn_mal = AsyncMock()
    mock_conn_mal.fetchrow = AsyncMock(return_value={
        "id": rfi_id,
        "case_id": case_id,
        "recipient_role": "CUSTOMER",
        "status": "OPEN",
        "expires_at": expires,
    })
    ctx_mal = AsyncMock()
    ctx_mal.__aenter__.return_value = mock_conn_mal
    ctx_mal.__aexit__.return_value = None

    with patch("routers.rfi.get_async_db_conn", return_value=ctx_mal):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res_mal = await ac.post(
                f"/api/v1/rfi/public/{raw_token}/submit",
                headers={"X-CSRF-Protection": "1"},
                data={"response_notes": "Attaching invoice"},
                files={"file": ("invoice.txt", EICAR_SIGNATURE, "text/plain")},
            )
            assert res_mal.status_code == 422

    # 3. Clean PDF upload succeeds, returns SHA-256 receipt, resumes SLA clock & notifies investigator
    mock_conn_ok = AsyncMock()
    mock_conn_ok.fetchrow = AsyncMock(side_effect=[
        {"id": rfi_id, "case_id": case_id, "recipient_role": "CUSTOMER", "status": "OPEN", "expires_at": expires},
        {"sla_paused_at": datetime.now(timezone.utc) - timedelta(minutes=10), "sla_paused_seconds": 0, "status": "PENDING_EDD"},
    ])
    mock_conn_ok.fetchval = AsyncMock(side_effect=[uuid.uuid4(), uuid.uuid4(), None])
    mock_conn_ok.execute = AsyncMock()
    ctx_ok = AsyncMock()
    ctx_ok.__aenter__.return_value = mock_conn_ok
    ctx_ok.__aexit__.return_value = None

    mock_backend = AsyncMock()
    mock_backend.backend_name = "local"
    mock_backend.put_object = AsyncMock(return_value="/tmp/rfi_doc.pdf")
    mock_backend.delete_object = AsyncMock()

    with patch("routers.rfi.get_async_db_conn", return_value=ctx_ok), \
         patch("routers.rfi.get_evidence_storage_backend", return_value=mock_backend):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res_ok = await ac.post(
                f"/api/v1/rfi/public/{raw_token}/submit",
                headers={"X-CSRF-Protection": "1"},
                data={"response_notes": "Source of funds verified via audited property sale contract."},
                files={"file": ("contract.pdf", b"%PDF-1.4 clean source of funds contract", "application/pdf")},
            )
            assert res_ok.status_code == 200
            body_ok = res_ok.json()
            assert body_ok["status"] == "SUBMITTED"
            assert body_ok["document_received"] == "contract.pdf"
            assert len(body_ok["sha256_receipt"]) == 64

    # 4. Already-submitted token returns 410 Gone
    mock_conn_done = AsyncMock()
    mock_conn_done.fetchrow = AsyncMock(return_value={
        "id": rfi_id, "case_id": case_id, "recipient_role": "CUSTOMER", "status": "SUBMITTED", "expires_at": expires,
    })
    ctx_done = AsyncMock()
    ctx_done.__aenter__.return_value = mock_conn_done
    ctx_done.__aexit__.return_value = None

    with patch("routers.rfi.get_async_db_conn", return_value=ctx_done):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res_gone = await ac.post(
                f"/api/v1/rfi/public/{raw_token}/submit",
                headers={"X-CSRF-Protection": "1"},
                data={"response_notes": "Replay submission"},
            )
            assert res_gone.status_code == 410


# ── P2-2: Grounded SAR Co-Pilot (PII Tokenization + Numeric Guardrail) ─────────
def test_p2_2_pii_tokenization_and_numeric_hallucination_guardrail():
    raw = "Subject Viktor Krum (Account DE8937040044) wired USD 49,500.00 to Acme Offshore."
    masked, rev = tokenize_pii_for_llm(raw, {
        "[SUBJECT_1]": "Viktor Krum",
        "[ACCT_1]": "DE8937040044",
    })
    assert "Viktor Krum" not in masked
    assert "DE8937040044" not in masked
    assert "[SUBJECT_1]" in masked and "[ACCT_1]" in masked
    assert detokenize_pii_from_llm(masked, rev) == raw

    ok, bad = verify_grounded_monetary_figures("Total volume USD 49,500.00 structured below $10,000.", [49500.0])
    assert ok is True and bad == []

    ok_halluc, bad_halluc = verify_grounded_monetary_figures("Subject laundered $999,999.00 via crypto.", [49500.0])
    assert ok_halluc is False
    assert "999,999.00" in bad_halluc


@pytest.mark.anyio
async def test_p2_2_sar_copilot_endpoint_emits_verified_citations():
    token = _make_token(role="L2_INVESTIGATOR", username="l2.alex")
    alert_id = str(uuid.uuid4())
    case_id = str(uuid.uuid4())

    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value=None)  # falls back cleanly to deterministic context
    mock_conn.fetch = AsyncMock(side_effect=[
        [{"id": uuid.uuid4(), "file_name": "wire_receipt.pdf", "sha256_digest": "abcdef1234567890" * 4}],
        [{"author_username": "l2.alex", "note": "Verified mismatch with declared business.", "created_at": datetime.now(timezone.utc)}],
    ])
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn
    ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("database.postgres.get_async_db_read_conn", return_value=ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                "/api/v1/fincen/sar/copilot",
                headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"},
                json={"alert_id": alert_id, "case_id": case_id},
            )
            assert res.status_code == 200
            body = res.json()
            assert body["pii_tokenized"] is True
            assert body["hallucination_check"] == "PASSED"
            tags = [c["tag"] for c in body["citations"]]
            assert any(t.startswith("[TX:") for t in tags)
            assert any(t.startswith("[EV:wire_receipt.pdf#sha256:abcdef123456]") for t in tags)


# ── P2-3: Cryptographically Signed Examiner Packet & Time-Boxed Auditor Room ───
@pytest.mark.anyio
async def test_p2_3_signed_examiner_packet_verifies_rs256_and_detects_tampering():
    token = _make_token(role="MLRO", username="mlro.elena")
    case_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={
        "id": case_id,
        "tenant_id": uuid.UUID(TENANT_ID),
        "case_number": "CASE-2026-EXAM99",
        "title": "Offshore Structuring Examination",
        "status": "CLOSED",
        "priority": "CRITICAL",
        "created_at": now,
    })
    mock_conn.fetch = AsyncMock(side_effect=[
        [],  # case_alerts
        [],  # sar_drafts
        [{"id": uuid.uuid4(), "file_name": "bank_stmt.pdf", "mime_type": "application/pdf", "file_size_bytes": 1024, "sha256_digest": "a" * 64, "storage_backend": "s3", "scan_status": "CLEAN", "uploaded_by_username": "l2.alex", "uploaded_at": now}],
        [],  # case_notes
        [],  # audit_log
    ])
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn
    ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("routers.audit.get_async_db_read_conn", return_value=ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                f"/api/v1/audit/examiner-packet/{case_id}",
                headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"},
            )
            assert res.status_code == 200
            assert res.headers["X-Packet-Signature-Alg"] == "RS256"
            assert len(res.headers["X-Packet-SHA256"]) == 64

            with zipfile.ZipFile(io.BytesIO(res.content), "r") as zf:
                names = set(zf.namelist())
                assert {"manifest.json", "signature.sig", "summary.html", "transactions.csv", "audit_trail.json", "evidence_manifest.json"}.issubset(names)
                manifest_bytes = zf.read("manifest.json")
                sig_b64 = zf.read("signature.sig").decode("ascii")

                # Genuine signature verifies cleanly
                assert verify_examiner_packet_signature(manifest_bytes, sig_b64) is True
                # 1-byte tamper MUST fail cryptographic verification
                assert verify_examiner_packet_signature(manifest_bytes + b" ", sig_b64) is False


@pytest.mark.anyio
async def test_p2_3_auditor_room_enforces_case_allowlist_and_revocation():
    raw_token, _ = generate_auditor_room_token(TENANT_ID)
    allowed_case = uuid.uuid4()
    forbidden_case = uuid.uuid4()
    future_exp = datetime.now(timezone.utc) + timedelta(hours=24)

    # 1. Requesting an out-of-scope case packet MUST return 403
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={
        "id": uuid.uuid4(),
        "room_name": "OCC 2026 Exam",
        "examiner_org": "OCC",
        "allowed_case_ids": [allowed_case],
        "expires_at": future_exp,
        "revoked_at": None,
    })
    mock_conn.execute = AsyncMock()
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn
    ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("routers.audit.get_async_db_conn", return_value=ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res_forbid = await ac.get(f"/api/v1/audit/rooms/{raw_token}/packet/{forbidden_case}")
            assert res_forbid.status_code == 403
            assert "outside the authorized Auditor Room scope" in res_forbid.json()["detail"]

    # 2. Revoked room MUST return 403
    mock_conn_rev = AsyncMock()
    mock_conn_rev.fetchrow = AsyncMock(return_value={
        "id": uuid.uuid4(),
        "room_name": "Revoked Exam",
        "examiner_org": "OCC",
        "allowed_case_ids": [allowed_case],
        "expires_at": future_exp,
        "revoked_at": datetime.now(timezone.utc),
    })
    ctx_rev = AsyncMock()
    ctx_rev.__aenter__.return_value = mock_conn_rev
    ctx_rev.__aexit__.return_value = None

    with patch("routers.audit.get_async_db_conn", return_value=ctx_rev):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res_rev = await ac.get(f"/api/v1/audit/rooms/{raw_token}/view")
            assert res_rev.status_code == 403


# ── P2-4: Multi-Layer Corporate UBO Ownership (>25% Split-Stake + Cycle Guard) ─
def test_p2_4_ubo_resolver_computes_indirect_split_ownership_and_cycle_guard():
    edges = [
        # Split ownership: Oleg owns 50% of Shell A (30% of OpCo) = 15% AND 50% of Shell B (30% of OpCo) = 15% -> 30% TOTAL > 25%!
        {"parent_entity_name": "Shell A Ltd", "parent_entity_type": "COMPANY", "child_company_name": "OpCo Trading", "ownership_pct": 30.0, "jurisdiction": "VG"},
        {"parent_entity_name": "Shell B Ltd", "parent_entity_type": "COMPANY", "child_company_name": "OpCo Trading", "ownership_pct": 30.0, "jurisdiction": "KY"},
        {"parent_entity_name": "Oleg Volkov", "parent_entity_type": "PERSON", "child_company_name": "Shell A Ltd", "ownership_pct": 50.0, "jurisdiction": "CY"},
        {"parent_entity_name": "Oleg Volkov", "parent_entity_type": "PERSON", "child_company_name": "Shell B Ltd", "ownership_pct": 50.0, "jurisdiction": "CY"},
        # Circular edge to verify cycle guard terminates cleanly
        {"parent_entity_name": "OpCo Trading", "parent_entity_type": "COMPANY", "child_company_name": "Shell A Ltd", "ownership_pct": 10.0, "jurisdiction": "VG"},
    ]

    tree = resolve_ubo_ownership_tree(edges, target_company="OpCo Trading", threshold_pct=25.0)
    assert tree["cycles_detected"] is True
    assert tree["ubo_count_above_threshold"] == 1
    oleg = tree["ultimate_beneficial_owners"][0]
    assert oleg["entity_name"] == "Oleg Volkov"
    assert oleg["effective_ownership_pct"] == 30.0
    assert oleg["exceeds_threshold"] is True
    assert oleg["is_split_ownership"] is True
    assert len(oleg["paths"]) == 2


# ── P2-5: Live Adverse Media NLP & Entity Disambiguation ───────────────────────
@pytest.mark.anyio
async def test_p2_5_adverse_media_disambiguation_and_namesake_suppression():
    # Genuine same-sentence financial crime hit -> high confidence
    real_hit = disambiguate_adverse_hit(
        "Viktor Krum",
        "Federal prosecutors indicted Viktor Krum on money laundering and sanctions evasion charges in Cyprus.",
        country="Cyprus",
    )
    assert real_hit["match_found"] is True
    assert real_hit["same_sentence_match"] is True
    assert real_hit["disambiguation_confidence"] >= 0.85
    assert "FINANCIAL_CRIME" in real_hit["matched_categories"]
    assert "SANCTIONS_EVASION" in real_hit["matched_categories"]

    # False-positive namesake in sports article where crime keyword is in an unrelated sentence
    fp_hit = disambiguate_adverse_hit(
        "Michael Jordan",
        "Michael Jordan celebrated the basketball championship victory at the stadium last night. Meanwhile, a separate bank faced a fraud inquiry.",
    )
    assert fp_hit["false_positive_suppressed"] is True
    assert fp_hit["match_found"] is False

    # Live screen aggregation with mocked GDELT articles
    live_res = await screen_live_adverse_media(
        subject_name="Viktor Krum",
        country="Cyprus",
        articles_override=[
            {
                "title": "Viktor Krum indicted in Cyprus money laundering shell company probe",
                "snippet": "Regulators linked Viktor Krum to offshore shell company fraud.",
                "url": "https://news.example.com/krum-indictment",
                "domain": "news.example.com",
                "seendate": "20261120T120000Z",
            }
        ],
    )
    assert live_res["adverse_hits_count"] == 1
    assert live_res["highest_risk_score"] >= 0.70
    assert live_res["edd_recommended"] is True


@pytest.mark.anyio
async def test_audit_360_deep_review_polish():
    """Verifies IAM readiness valid JSON + close_redis_client, customer UUID activity query, feature store ZREMRANGEBYSCORE, and VaultSecretsLoader.shutdown."""
    from database.redis_db import close_redis_client
    from routers.customers import _fetch_customer_activity
    from services.feature_store import record_transaction_feature_event
    from services.iam.app import iam_app
    from services.vault_loader import VaultSecretsLoader

    assert callable(close_redis_client)
    await VaultSecretsLoader.shutdown()

    # 1. IAM /health/readiness returns valid JSON (not Python dict repr)
    iam_transport = ASGITransport(app=iam_app)
    async with httpx.AsyncClient(transport=iam_transport, base_url="http://test") as ac:
        res = await ac.get("/health/readiness")
        parsed = json.loads(res.text)
        assert parsed["status"] in ("UP", "DOWN")
        assert isinstance(parsed["checks"], dict)

    # 2. _fetch_customer_activity passes acc_uuid (UUID) into PostgreSQL queries
    acc_uuid = uuid.uuid4()
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[])
    await _fetch_customer_activity(mock_conn, "DE8937040044", acc_uuid)
    for call in mock_conn.fetch.call_args_list:
        assert call.args[1] == acc_uuid

    # 3. Feature store calls zremrangebyscore to bound 30-day sorted sets
    mock_redis = AsyncMock()
    with patch("services.feature_store.get_async_redis_client", AsyncMock(return_value=mock_redis)):
        await record_transaction_feature_event("ACC-1", 500.0, "tx-1", ts_epoch=1700000000.0)
        assert mock_redis.zadd.called
        assert mock_redis.zremrangebyscore.called
        assert mock_redis.expire.called
