"""
P0 Enterprise & Regulatory Launch Readiness Verification Suite (P0-1 through P0-6)
"""

import io
import json
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt
import pytest
from httpx import ASGITransport

from main import app
from services.auth import create_access_token
from services.evidence_storage import (
    EICAR_SIGNATURE,
    S3EvidenceBackend,
    compute_sha256_hex,
    scan_bytes_for_malware,
)
from services.fx_rates import convert_to_base_currency
from services.goaml import generate_goaml_xml
from services.sar_validator import validate_regulatory_xml
from services.secrets_manager import get_or_create_rsa_keypair
from services.sso import (
    generate_pkce_pair,
    resolve_role_from_groups,
    store_sso_state,
    verify_oidc_id_token,
)
from services.travel_rule import validate_travel_rule
from services.webhooks import sign_webhook_payload, verify_webhook_signature

TENANT_ID = "00000000-0000-0000-0000-000000000001"


def _token(role: str = "ADMIN", username: str = "p0_admin") -> str:
    return create_access_token({
        "sub": str(uuid.uuid4()),
        "role": role,
        "username": username,
        "tenant_id": TENANT_ID,
    })


# ── P0-1: Multi-Currency FX Normalization & Travel Rule ────────────────────────
@pytest.mark.anyio
async def test_p0_1_fx_normalization_jpy_vs_gbp():
    """¥15,000 JPY (~$99) must stay below $10K while £8,500 GBP (~$10,795) exceeds $10K."""
    jpy_usd, jpy_rate = await convert_to_base_currency(15000.0, "JPY", "USD")
    assert jpy_usd < 200.0
    assert jpy_rate < 0.02

    gbp_usd, gbp_rate = await convert_to_base_currency(8500.0, "GBP", "USD")
    assert gbp_usd > 10000.0
    assert gbp_rate > 1.1


def test_p0_1_travel_rule_multicurrency_thresholds():
    """Travel Rule enforces $3,000 USD equivalent for JPY/GBP and €1,000 EUR for EUR."""
    empty_party = {}
    # ¥15,000 JPY (~$99) is far below $3,000 -> exempt
    ok_jpy, missing_jpy = validate_travel_rule(15000.0, "JPY", "WIRE", empty_party, empty_party)
    assert ok_jpy is True
    assert missing_jpy == []

    # £3,000 GBP (~$3,810) exceeds $3,000 -> must require originator/beneficiary fields
    ok_gbp, missing_gbp = validate_travel_rule(3000.0, "GBP", "SWIFT", empty_party, empty_party)
    assert ok_gbp is False
    assert "originator_name" in missing_gbp

    # €1,200 EUR exceeds EU TFR €1,000 -> must require fields; €800 EUR exempt
    ok_eur_high, _ = validate_travel_rule(1200.0, "EUR", "SEPA", empty_party, empty_party)
    ok_eur_low, _ = validate_travel_rule(800.0, "EUR", "SEPA", empty_party, empty_party)
    assert ok_eur_high is False
    assert ok_eur_low is True


# ── P0-2: Signed Outbound Core-Banking Webhooks & Persisted SIEM ───────────────
def test_p0_2_webhook_hmac_signature_roundtrip():
    secret = "whsec_test_secret_12345"
    ts = "1795180000"
    body = b'{"event_type":"ACCOUNT_FROZEN","account_id":"123"}'
    sig = sign_webhook_payload(secret, ts, body)
    assert sig.startswith("sha256=")
    assert verify_webhook_signature(secret, ts, body, sig) is True
    assert verify_webhook_signature(secret, ts, body + b"x", sig) is False


@pytest.mark.anyio
async def test_p0_2_webhook_create_blocks_ssrf_and_freeze_enqueues_outbox():
    token = _token("ADMIN")
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        # Private metadata IP must be rejected with 400
        res_ssrf = await ac.post(
            "/api/v1/admin/webhooks",
            headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"},
            json={"name": "Bad Hook", "url": "https://169.254.169.254/latest/meta-data/"},
        )
        assert res_ssrf.status_code == 400

    # Verify freeze_account atomically records WEBHOOK_DISPATCH in transactional_outbox
    acc_id = str(uuid.uuid4())
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={"id": uuid.UUID(acc_id), "status": "ACTIVE", "account_number": "ACCT-99"})
    mock_conn.execute = AsyncMock()
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.accounts.get_async_db_conn", return_value=mock_ctx), \
         patch("routers.accounts.record_audit_event_tx", AsyncMock()), \
         patch("services.webhooks.record_outbox_event", AsyncMock(return_value=str(uuid.uuid4()))) as mock_outbox:
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res_freeze = await ac.post(
                f"/api/v1/accounts/{acc_id}/freeze",
                headers={"Authorization": f"Bearer {_token('MLRO')}", "X-CSRF-Protection": "1"},
                json={"reason": "Court order freeze mandate", "freezing_order_ref": "ORD-2026-9"},
            )
            assert res_freeze.status_code == 200
            mock_outbox.assert_awaited_once()
            call_kwargs = mock_outbox.call_args.kwargs
            assert call_kwargs["aggregate_type"] == "WEBHOOK_DISPATCH"
            assert call_kwargs["event_type"] == "ACCOUNT_FROZEN"


# ── P0-3: S3/GCS WORM Evidence Storage + SHA-256 + Malware Scan ────────────────
@pytest.mark.anyio
async def test_p0_3_evidence_rejects_eicar_malware_and_computes_sha256():
    is_clean, status_label = await scan_bytes_for_malware(b"prefix " + EICAR_SIGNATURE + b" suffix")
    assert is_clean is False
    assert "INFECTED" in status_label

    token = _token("L2_INVESTIGATOR")
    case_id = str(uuid.uuid4())
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.post(
            f"/api/v1/cases/{case_id}/evidence",
            headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"},
            files={"file": ("statement.txt", io.BytesIO(EICAR_SIGNATURE), "text/plain")},
        )
        assert res.status_code == 422
        assert "malware" in res.json()["detail"].lower()


@pytest.mark.anyio
async def test_p0_3_s3_worm_backend_generates_sigv4_kms_and_worm_headers():
    backend = S3EvidenceBackend(
        bucket="aml-evidence-prod",
        region="us-east-1",
        access_key="AKIAEXAMPLEKEY",
        secret_key="SecretExampleKey1234567890",
        kms_key_id="arn:aws:kms:us-east-1:123456789012:key/test-key",
        worm_enabled=True,
    )
    captured = {}

    class DummyResp:
        status_code = 200
        text = "OK"

    async def fake_put(self, url, content=b"", headers=None):
        captured["url"] = url
        captured["headers"] = headers or {}
        return DummyResp()

    payload = b"%PDF-1.4 bank wire receipt"
    with patch.object(httpx.AsyncClient, "put", new=fake_put):
        uri = await backend.put_object(TENANT_ID, "ev1_receipt.pdf", payload, "application/pdf")

    assert uri == f"s3://aml-evidence-prod/evidence/{TENANT_ID}/ev1_receipt.pdf"
    hdrs = captured["headers"]
    assert hdrs["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEKEY/")
    assert hdrs["x-amz-server-side-encryption"] == "aws:kms"
    assert hdrs["x-amz-object-lock-mode"] == "COMPLIANCE"
    assert "x-amz-object-lock-retain-until-date" in hdrs
    assert hdrs["x-amz-content-sha256"] == compute_sha256_hex(payload)


# ── P0-4: SAR Statutory 30/90-Day Clocks & Strict Regulatory XML Validator ─────
def test_p0_4_regulatory_xml_validator_blocks_xxe_and_validates_fincen_and_goaml():
    xxe_xml = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><SuspiciousActivityReport>&xxe;</SuspiciousActivityReport>'
    ok_xxe, errs_xxe = validate_regulatory_xml(xxe_xml, "FINCEN_BSABATCH")
    assert ok_xxe is False
    assert any("XXE" in e or "DOCTYPE" in e for e in errs_xxe)

    bad_curr_xml = "<SuspiciousActivityReport><Currency>INVALID</Currency><Amount>-50</Amount><Narrative>Suspicious activity observed.</Narrative></SuspiciousActivityReport>"
    ok_bad, errs_bad = validate_regulatory_xml(bad_curr_xml, "FINCEN_BSABATCH")
    assert ok_bad is False
    assert len(errs_bad) >= 2

    valid_goaml = generate_goaml_xml(
        {
            "alert_id": str(uuid.uuid4()),
            "rule_name": "STRUCTURING_SMURFING",
            "threat_level": "HIGH",
            "risk_score": 0.91,
            "amount": 12500.0,
            "currency": "EUR",
            "sender_account": "DE89370400440532013000",
            "sender_name": "Sender Corp",
            "receiver_account": "CH9300762011623852957",
            "receiver_name": "Receiver SA",
        },
        narrative="Structured wire transfers detected across 48 hours.",
    )
    ok_goaml, errs_goaml = validate_regulatory_xml(valid_goaml, "GOAML_5")
    assert ok_goaml is True, f"Expected valid goAML XML, got errors: {errs_goaml}"


@pytest.mark.anyio
async def test_p0_4_sar_draft_sets_30day_statutory_deadline():
    draft_uuid = uuid.uuid4()
    alert_uuid = uuid.uuid4()
    mock_conn = AsyncMock()
    mock_conn.fetchval = AsyncMock(return_value=draft_uuid)
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("routers.fincen.get_async_db_conn", return_value=mock_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                "/api/v1/fincen/sar/drafts",
                headers={"Authorization": f"Bearer {_token('L2_INVESTIGATOR')}", "X-CSRF-Protection": "1"},
                json={
                    "alert_id": str(alert_uuid),
                    "narrative": "Detailed structuring typology confirmed across multiple wire transfers.",
                    "status": "PENDING_MLRO_REVIEW",
                },
            )
            assert res.status_code == 201
            body = res.json()
            assert body["days_until_deadline"] == 30
            assert body["statutory_deadline_at"] is not None


# ── P0-5: GDPR DSAR Tipping-Off Fix & Legal-Hold-Aware Erasure ─────────────────
@pytest.mark.anyio
async def test_p0_5_dsar_export_strips_legal_holds_and_risk_score():
    """31 U.S.C. § 5318(g)(2): Customer DSAR must NEVER disclose legal_holds_active or AML risk_score."""
    acc_uuid = uuid.uuid4()
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={
        "id": acc_uuid,
        "account_number": "ACCT-DSAR-01",
        "owner_name": "Jane Customer",
        "swift_bic": "CHASUS33",
        "status": "ACTIVE",
        "created_at": datetime.now(timezone.utc) - timedelta(days=400),
    })
    mock_conn.fetchval = AsyncMock(return_value=1)
    mock_conn.fetch = AsyncMock(return_value=[{
        "id": uuid.uuid4(),
        "amount": 500.0,
        "currency": "USD",
        "status": "COMPLETED",
        "timestamp": datetime.now(timezone.utc),
        "country": "US",
        "channel": "Wire",
    }])
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    transport = ASGITransport(app=app)
    with patch("routers.privacy.get_async_db_read_conn", return_value=mock_ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get(
                "/api/v1/privacy/dsar/export/ACCT-DSAR-01?page=1&limit=50",
                headers={"Authorization": f"Bearer {_token('MLRO')}"},
            )
            assert res.status_code == 200
            data = res.json()
            assert "legal_holds_active" not in data
            assert "risk_score" not in data["account"]
            assert data["tipping_off_sanitized"] is True
            assert data["pagination"]["total_transactions"] == 1


@pytest.mark.anyio
async def test_p0_5_gdpr_erasure_blocks_on_legal_hold_and_5yr_bsa_and_pseudonymizes_eligible():
    transport = ASGITransport(app=app)
    acc_uuid = uuid.uuid4()
    token = _token("MLRO")

    # Case 1: Active legal hold -> 409 Conflict
    mock_conn_hold = AsyncMock()
    mock_conn_hold.fetchrow = AsyncMock(return_value={
        "id": acc_uuid,
        "account_number": "ACCT-HOLD",
        "owner_name": "Held User",
        "created_at": datetime.now(timezone.utc) - timedelta(days=365 * 7),
        "erased_at": None,
    })
    mock_conn_hold.fetchval = AsyncMock(return_value=1)  # 1 active legal hold
    ctx_hold = AsyncMock()
    ctx_hold.__aenter__.return_value = mock_conn_hold
    ctx_hold.__aexit__.return_value = None

    with patch("routers.privacy.get_async_db_conn", return_value=ctx_hold):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                "/api/v1/privacy/erasure",
                headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"},
                json={"account_number": "ACCT-HOLD", "reason": "Customer GDPR Art 17 request"},
            )
            assert res.status_code == 409
            assert "legal hold" in res.json()["detail"].lower()

    # Case 2: Within 5-year BSA retention -> 409 Conflict
    mock_conn_bsa = AsyncMock()
    mock_conn_bsa.fetchrow = AsyncMock(return_value={
        "id": acc_uuid,
        "account_number": "ACCT-RECENT",
        "owner_name": "Recent User",
        "created_at": datetime.now(timezone.utc) - timedelta(days=200),
        "erased_at": None,
    })
    mock_conn_bsa.fetchval = AsyncMock(side_effect=[0, datetime.now(timezone.utc) - timedelta(days=30)])
    ctx_bsa = AsyncMock()
    ctx_bsa.__aenter__.return_value = mock_conn_bsa
    ctx_bsa.__aexit__.return_value = None

    with patch("routers.privacy.get_async_db_conn", return_value=ctx_bsa):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                "/api/v1/privacy/erasure",
                headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"},
                json={"account_number": "ACCT-RECENT", "reason": "Customer GDPR Art 17 request"},
            )
            assert res.status_code == 409
            assert "5-year bsa" in res.json()["detail"].lower()

    # Case 3: Eligible (>5 years, 0 holds) -> Pseudonymized
    mock_conn_ok = AsyncMock()
    mock_conn_ok.fetchrow = AsyncMock(return_value={
        "id": acc_uuid,
        "account_number": "ACCT-OLD",
        "owner_name": "Old User",
        "created_at": datetime.now(timezone.utc) - timedelta(days=365 * 6),
        "erased_at": None,
    })
    mock_conn_ok.fetchval = AsyncMock(side_effect=[0, datetime.now(timezone.utc) - timedelta(days=365 * 6)])
    mock_conn_ok.execute = AsyncMock()
    ctx_ok = AsyncMock()
    ctx_ok.__aenter__.return_value = mock_conn_ok
    ctx_ok.__aexit__.return_value = None

    with patch("routers.privacy.get_async_db_conn", return_value=ctx_ok):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.post(
                "/api/v1/privacy/erasure",
                headers={"Authorization": f"Bearer {token}", "X-CSRF-Protection": "1"},
                json={"account_number": "ACCT-OLD", "reason": "Post-retention GDPR Art 17 erasure"},
            )
            assert res.status_code == 200
            body = res.json()
            assert body["status"] == "ERASED_PSEUDONYMIZED"
            assert body["pseudonym"].startswith("ERASED-")


# ── P0-6: Enterprise OIDC SSO (PKCE + JWKS + Group-to-RBAC) ────────────────────
def test_p0_6_pkce_and_group_to_rbac_prevents_super_admin_escalation():
    verifier, challenge = generate_pkce_pair()
    assert len(verifier) >= 43
    assert len(challenge) >= 43
    assert verifier != challenge

    mapping = {
        "AML-L1": "L1_ANALYST",
        "AML-MLRO": "MLRO",
        "EVIL-ROOT": "SUPER_ADMIN",  # Must be ignored!
    }
    assert resolve_role_from_groups(["AML-L1", "AML-MLRO"], mapping) == "MLRO"
    assert resolve_role_from_groups(["EVIL-ROOT"], mapping, default_role="L1_ANALYST") == "L1_ANALYST"


@pytest.mark.anyio
async def test_p0_6_oidc_callback_verifies_state_jwks_and_jit_provisions_mlro():
    priv_pem, pub_pem = get_or_create_rsa_keypair()
    provider_id = str(uuid.uuid4())
    state_token = f"state_test_oidc_{uuid.uuid4().hex}"
    nonce = f"nonce_test_oidc_{uuid.uuid4().hex}"
    issuer = "https://idp.example.invalid"

    id_token = jwt.encode(
        {
            "iss": issuer,
            "sub": "okta-user-9988",
            "aud": "sentinel-client-id",
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=10)).timestamp()),
            "nonce": nonce,
            "email": "elena.mlro@bank.com",
            "groups": ["AML-MLRO"],
        },
        priv_pem,
        algorithm="RS256",
    )

    await store_sso_state(
        state_token,
        {
            "provider_id": provider_id,
            "tenant_id": TENANT_ID,
            "nonce": nonce,
            "code_verifier": "verifier_abc",
            "redirect_uri": f"http://test/api/v1/auth/sso/{provider_id}/callback",
        },
    )

    provider_row = {
        "id": uuid.UUID(provider_id),
        "tenant_id": uuid.UUID(TENANT_ID),
        "provider_name": "Okta Enterprise",
        "issuer_url": issuer,
        "client_id": "sentinel-client-id",
        "client_secret_enc": "",
        "scopes": "openid profile email groups",
        "group_role_mapping": {"AML-MLRO": "MLRO"},
        "default_role": "L1_ANALYST",
        "enabled": True,
    }
    discovery_doc = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/oauth2/v1/authorize",
        "token_endpoint": f"{issuer}/oauth2/v1/token",
        "jwks_uri": f"{issuer}/oauth2/v1/keys",
    }

    class DummyTokenResp:
        status_code = 200

        def json(self):
            return {"id_token": id_token, "access_token": "idp-access-token"}

    async def fake_post(self, url, data=None, **kwargs):
        return DummyTokenResp()

    mock_db_conn = AsyncMock()
    mock_db_conn.fetchrow = AsyncMock(return_value=None)
    mock_db_conn.execute = AsyncMock()
    mock_db_ctx = AsyncMock()
    mock_db_ctx.__aenter__.return_value = mock_db_conn
    mock_db_ctx.__aexit__.return_value = None

    def fake_verify(id_token, jwks_uri, client_id, issuer, expected_nonce):
        return verify_oidc_id_token(
            id_token=id_token,
            jwks_uri=jwks_uri,
            client_id=client_id,
            issuer=issuer,
            expected_nonce=expected_nonce,
            signing_key_override=pub_pem,
        )

    transport = ASGITransport(app=app)
    with patch("routers.sso._load_provider_for_login", AsyncMock(return_value=provider_row)), \
         patch("routers.sso.fetch_oidc_discovery", AsyncMock(return_value=discovery_doc)), \
         patch("routers.sso.verify_oidc_id_token", side_effect=fake_verify), \
         patch("routers.sso.get_async_db_conn", return_value=mock_db_ctx), \
         patch.object(httpx.AsyncClient, "post", new=fake_post):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            res = await ac.get(
                f"/api/v1/auth/sso/{provider_id}/callback?code=authcode123&state={state_token}",
                headers={"Accept": "application/json"},
            )
            assert res.status_code == 200
            body = res.json()
            assert body["username"] == "elena.mlro"
            assert body["role"] == "MLRO"
            assert "access_token" in res.cookies

            # Replaying the exact same single-use state token must fail with 401
            res_replay = await ac.get(
                f"/api/v1/auth/sso/{provider_id}/callback?code=authcode123&state={state_token}",
                headers={"Accept": "application/json"},
            )
            assert res_replay.status_code == 401
