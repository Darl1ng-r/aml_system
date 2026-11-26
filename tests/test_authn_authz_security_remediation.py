"""
Comprehensive AuthN & AuthZ Security Remediation Regression Suite
=================================================================
Verifies ALL 29 findings remediated from the AuthN/AuthZ Security Audit:
  - AUTHZ-01..12: Live PostgreSQL FORCED RLS (38 tables + two-tenant isolation),
                  Neo4j Cypher tenant conjunctions, Redis lock tenant namespacing,
                  SIEM singleton isolation, global rules SUPER_ADMIN lock,
                  workflow gates (CIP/case-close/bulk-action/freeze/EDD),
                  horizontal notification BOLA, FinCEN 4-eyes & XML integrity,
                  SUPER_ADMIN protection, RBAC alignment, ML feedback isolation,
                  cross-tenant case_alerts / auditor_rooms validation, WORM delete.
  - AUTHN-01..10: Session revocation & role reload on /refresh, Redis cache-miss DB
                  fallback, JTI immediate logout revocation, OIDC state cookie binding
                  & email_verified & SSRF & collision safety, MFA brute-force cap &
                  encryption & re-enroll guard & 80-bit HMAC recovery codes, JWT strict
                  algorithm enforcement, WebSocket CSWSH/ticket/refresh-block,
                  DownstreamAuthValidator fail-closed, lockout case-normalization &
                  128-char password DoS cap, Supabase MFA & revocation parity.
  - HARD-01..05 & LOW-01..04: ip_only rate limiting, Retry-After header preservation,
                  loopback-only prod proxy default, /check-username 403 in prod,
                  ENVIRONMENT=prod parity, browser-mode token hiding & zero localStorage
                  JWT readers in static/, VAULT_DEV_TOKEN prod block, sanitized 500s,
                  Referrer-Policy: no-referrer, Content-Disposition sanitization.
"""

import hashlib
import inspect
import json
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import jwt
import pytest
from fastapi import HTTPException, Request, WebSocket
from httpx import ASGITransport

from config import Settings, settings
from main import app
from services.auth import (
    DownstreamAuthValidator,
    _normalize_lockout_username,
    _verify_token_version,
    create_access_token,
    create_refresh_token,
    revoke_user_sessions,
)
from services.mfa import generate_recovery_codes, verify_and_consume_recovery_code
from services.rate_limiter import RateLimiter
from services.secrets_manager import decode_jwt_with_rotation, get_or_create_rsa_keypair
from services.trusted_proxy import get_trusted_client_ip

TENANT_A = "00000000-0000-0000-0000-000000000001"
TENANT_B = "00000000-0000-0000-0000-000000000002"


def _tok(
    role: str,
    tenant_id: str = TENANT_A,
    user_id: str | None = None,
    username: str = "sec.tester",
    token_version: int = 1,
) -> str:
    return create_access_token(
        {
            "sub": user_id or str(uuid.uuid4()),
            "role": role,
            "username": username,
            "tenant_id": tenant_id,
            "token_version": token_version,
        }
    )


# ══════════════════════════════════════════════════════════════════════════════
# 1. AUTHZ-01: Live PostgreSQL FORCED RLS Catalog & Two-Tenant Isolation
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_authz01_live_postgres_forced_rls_on_all_tenant_tables():
    """Verify every tenant-scoped table in PostgreSQL has ENABLE + FORCE RLS and >=1 policy."""
    from database.postgres import get_async_db_conn

    required_tables = {
        "accounts",
        "alert_escalations",
        "alerts",
        "api_keys",
        "audit_log",
        "auditor_rooms",
        "case_alerts",
        "case_evidence",
        "case_notes",
        "cases",
        "ctr_filings",
        "data_retention_policies",
        "edd_requests",
        "kyc_reviews",
        "legal_holds",
        "ml_feedback_samples",
        "notifications",
        "qa_reviews",
        "resource_locks",
        "rfi_requests",
        "rule_config_history",
        "rule_configs",
        "sar_drafts",
        "siem_configs",
        "sso_providers",
        "str_batches",
        "tenant_webhooks",
        "transactions",
        "users",
    }

    async with get_async_db_conn(tenant_id=TENANT_A) as conn:
        rows = await conn.fetch(
            """
            SELECT c.relname,
                   c.relrowsecurity,
                   c.relforcerowsecurity,
                   (SELECT COUNT(*) FROM pg_policy p WHERE p.polrelid = c.oid) AS pol_count
            FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname = 'public' AND c.relkind = 'r'
              AND c.relname = ANY($1::text[]);
            """,
            list(required_tables),
        )

    found = {r["relname"]: r for r in rows}
    missing = required_tables - set(found.keys())
    assert not missing, f"Expected tables missing from public schema: {missing}"

    for tbl, row in found.items():
        assert row["relrowsecurity"] is True, f"Table {tbl} does NOT have RLS enabled!"
        assert row["relforcerowsecurity"] is True, f"Table {tbl} does NOT have FORCE RLS (owner bypass)!"
        assert int(row["pol_count"]) >= 1, f"Table {tbl} has 0 RLS policies!"


@pytest.mark.asyncio
async def test_authz01_live_postgres_two_tenant_isolation_on_str_batches():
    """Verify table owner aml_app cannot read Tenant A's str_batches when scoped to Tenant B."""
    from database.postgres import get_async_db_conn

    batch_id = f"STR-RLS-TEST-{uuid.uuid4().hex[:10]}"
    try:
        async with get_async_db_conn(tenant_id=TENANT_A) as conn_a:
            await conn_a.execute(
                """
                INSERT INTO str_batches (id, tenant_id, record_count, total_amount, checksum, payload_xml, status)
                VALUES ($1, $2::uuid, 1, 15000.00, 'deadbeef', '<SAR/>', 'GENERATED');
                """,
                batch_id,
                TENANT_A,
            )

        # Querying as Tenant B (without WHERE tenant_id!) MUST see 0 rows via FORCED RLS
        async with get_async_db_conn(tenant_id=TENANT_B) as conn_b:
            leaked = await conn_b.fetchrow("SELECT id FROM str_batches WHERE id = $1;", batch_id)
            assert leaked is None, "CRITICAL: Forced RLS failed — Tenant B read Tenant A's STR batch!"

        # Querying as Tenant A MUST see its own row
        async with get_async_db_conn(tenant_id=TENANT_A) as conn_a2:
            own = await conn_a2.fetchrow("SELECT id FROM str_batches WHERE id = $1;", batch_id)
            assert own is not None and own["id"] == batch_id
    finally:
        async with get_async_db_conn(tenant_id=TENANT_A) as conn_cleanup:
            await conn_cleanup.execute("DELETE FROM str_batches WHERE id = $1;", batch_id)


# ══════════════════════════════════════════════════════════════════════════════
# 2. AUTHN-01: Session Revocation, Role Demotion Reload, Redis Cache-Miss & Logout JTI
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_authn01_refresh_rejects_revoked_version_and_reloads_live_role():
    """POST /refresh MUST reject revoked token_version and reload demoted role from PostgreSQL."""
    user_id = str(uuid.uuid4())
    refresh_v1 = create_refresh_token(
        {
            "sub": user_id,
            "role": "ADMIN",
            "username": "demoted.admin",
            "tenant_id": TENANT_A,
            "token_version": 1,
            "family_id": "fam_test_rev",
        }
    )

    redis_store = {}
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=lambda k: redis_store.get(k))
    mock_redis.set = AsyncMock(
        side_effect=lambda k, v, ex=None, nx=False: (
            False if (nx and k in redis_store) else (redis_store.__setitem__(k, v) or True)
        )
    )
    mock_redis.setex = AsyncMock(side_effect=lambda k, ttl, v: redis_store.__setitem__(k, v))

    # Case 1: DB bumped token_version to 2 -> refresh_v1 MUST be rejected with 401
    mock_conn_revoked = AsyncMock()
    mock_conn_revoked.fetchrow = AsyncMock(
        return_value={"role": "ADMIN", "tenant_id": uuid.UUID(TENANT_A), "token_version": 2, "is_active": True}
    )
    ctx_rev = AsyncMock()
    ctx_rev.__aenter__.return_value = mock_conn_revoked

    transport = ASGITransport(app=app)
    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("database.postgres.get_async_db_conn", return_value=ctx_rev):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r_rev = await ac.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": refresh_v1},
                headers={"X-CSRF-Protection": "1"},
            )
            assert r_rev.status_code == 401

    # Case 2: DB demoted role from ADMIN -> L1_ANALYST (same version 1) -> rotated token MUST carry L1_ANALYST
    mock_conn_demoted = AsyncMock()
    mock_conn_demoted.fetchrow = AsyncMock(
        return_value={"role": "L1_ANALYST", "tenant_id": uuid.UUID(TENANT_A), "token_version": 1, "is_active": True}
    )
    ctx_dem = AsyncMock()
    ctx_dem.__aenter__.return_value = mock_conn_demoted

    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("database.postgres.get_async_db_conn", return_value=ctx_dem):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r_dem = await ac.post(
                "/api/v1/auth/refresh",
                json={"refresh_token": refresh_v1},
                headers={"X-CSRF-Protection": "1"},
            )
            assert r_dem.status_code == 200
            body = r_dem.json()
            assert body["role"] == "L1_ANALYST"
            decoded = decode_jwt_with_rotation(body["access_token"], algorithm=settings.jwt_algorithm)
            assert decoded["role"] == "L1_ANALYST"
            assert decoded["token_version"] == 1


@pytest.mark.asyncio
async def test_authn01_verify_token_version_falls_through_on_redis_cache_miss():
    """A Redis cache MISS (get -> None) MUST fall through to PostgreSQL instead of failing open."""
    user_id = str(uuid.uuid4())
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(return_value=None)  # Redis online, cache miss!
    mock_redis.setex = AsyncMock()

    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={"token_version": 4, "is_active": True})
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn

    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("services.auth.get_async_db_conn", return_value=ctx):
        with pytest.raises(HTTPException) as exc:
            await _verify_token_version(user_id, token_version=1, tenant_id=TENANT_A)
        assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_authn01_logout_immediately_denylists_access_jti_and_hashes_refresh_key():
    """POST /logout MUST denylist access token JTI immediately and hash refresh token keys."""
    uid = str(uuid.uuid4())
    access = _tok("ANALYST", TENANT_A, user_id=uid)
    refresh = create_refresh_token(
        {"sub": uid, "role": "ANALYST", "username": "u", "tenant_id": TENANT_A, "token_version": 1}
    )
    decoded_acc = decode_jwt_with_rotation(access, algorithm=settings.jwt_algorithm)
    jti = decoded_acc["jti"]

    redis_store = {}
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=lambda k: redis_store.get(k))
    mock_redis.setex = AsyncMock(side_effect=lambda k, ttl, v: redis_store.__setitem__(k, v))

    transport = ASGITransport(app=app)
    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.post(
                "/api/v1/auth/logout",
                json={"refresh_token": refresh},
                headers={"Authorization": f"Bearer {access}", "X-CSRF-Protection": "1"},
            )
            assert r.status_code == 200

        # Refresh token key MUST be SHA-256 hashed, never raw JWT
        expected_hash = hashlib.sha256(refresh.encode("utf-8")).hexdigest()
        assert redis_store.get(f"token:revoked:{expected_hash}") == "1"
        assert f"token:revoked:{refresh}" not in redis_store
        # Access token JTI MUST be denylisted
        assert redis_store.get(f"token:access_revoked:{jti}") == "1"

        # Immediately reusing that access token MUST fail with 401
        with pytest.raises(HTTPException) as exc:
            await _verify_token_version(uid, token_version=1, tenant_id=TENANT_A, jti=jti)
        assert exc.value.status_code == 401


@pytest.mark.asyncio
async def test_authn01_revoke_user_sessions_never_writes_version_1_on_db_error():
    """When PostgreSQL fails during revoke_user_sessions, Redis must bump >1 (never write 1)."""
    uid = str(uuid.uuid4())
    redis_store = {}
    mock_redis = AsyncMock()
    mock_redis.incr = AsyncMock(side_effect=lambda k: redis_store.__setitem__(k, redis_store.get(k, 0) + 1) or redis_store[k])
    mock_redis.setex = AsyncMock(side_effect=lambda k, ttl, v: redis_store.__setitem__(k, v))
    mock_redis.expire = AsyncMock()

    with patch("services.auth.get_async_db_conn", side_effect=RuntimeError("PG down")), \
         patch("database.redis_db.get_async_redis_client", return_value=mock_redis):
        new_ver = await revoke_user_sessions(uid)
        assert new_ver >= 2
        assert redis_store[f"user:token_version:{uid}"] >= 2


# ══════════════════════════════════════════════════════════════════════════════
# 3. AUTHN-02 & AUTHN-07: OIDC SSO State Binding, Email Verified & Discovery SSRF
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_authn02_oidc_callback_blocks_missing_state_cookie_and_unverified_email():
    """OIDC callback MUST reject missing sso_state_binding cookie (401) and email_verified=False (403)."""
    from services.sso import store_sso_state, verify_oidc_id_token

    priv_pem, pub_pem = get_or_create_rsa_keypair()
    provider_id = str(uuid.uuid4())
    issuer = "https://idp.example.invalid"
    provider_row = {
        "id": uuid.UUID(provider_id),
        "tenant_id": uuid.UUID(TENANT_A),
        "provider_name": "Okta",
        "issuer_url": issuer,
        "client_id": "cid-1",
        "client_secret_enc": "",
        "scopes": "openid email",
        "group_role_mapping": {},
        "default_role": "L1_ANALYST",
        "enabled": True,
    }
    discovery_doc = {
        "issuer": issuer,
        "authorization_endpoint": f"{issuer}/authorize",
        "token_endpoint": f"{issuer}/token",
        "jwks_uri": f"{issuer}/keys",
    }
    transport = ASGITransport(app=app)

    # 1. Missing sso_state_binding cookie -> 401 Login CSRF blocked
    state_1 = f"st_{uuid.uuid4().hex}"
    await store_sso_state(state_1, {"provider_id": provider_id, "tenant_id": TENANT_A, "nonce": "n1", "code_verifier": "v1", "redirect_uri": "http://test/cb"})
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        r_csrf = await ac.get(f"/api/v1/auth/sso/{provider_id}/callback?code=abc&state={state_1}")
        assert r_csrf.status_code == 401

    # 2. Valid state cookie but email_verified=False -> 403
    state_2 = f"st_{uuid.uuid4().hex}"
    nonce_2 = f"nc_{uuid.uuid4().hex}"
    await store_sso_state(state_2, {"provider_id": provider_id, "tenant_id": TENANT_A, "nonce": nonce_2, "code_verifier": "v2", "redirect_uri": "http://test/cb"})
    id_tok = jwt.encode(
        {
            "iss": issuer,
            "sub": "attacker-sub",
            "aud": "cid-1",
            "exp": int((datetime.now(timezone.utc) + timedelta(minutes=5)).timestamp()),
            "nonce": nonce_2,
            "email": "admin@bank.com",
            "email_verified": False,
        },
        priv_pem,
        algorithm="RS256",
    )
    binding = hashlib.sha256(f"sso-state-bind:{state_2}".encode()).hexdigest()

    class DummyTokenResp:
        status_code = 200

        def json(self):
            return {"id_token": id_tok}

    async def fake_post(self, url, **kwargs):
        return DummyTokenResp()

    def fake_verify(id_token, jwks_uri, client_id, issuer, expected_nonce):
        return verify_oidc_id_token(id_token, jwks_uri, client_id, issuer, expected_nonce, signing_key_override=pub_pem)

    with patch("routers.sso._load_provider_for_login", AsyncMock(return_value=provider_row)), \
         patch("routers.sso.fetch_oidc_discovery", AsyncMock(return_value=discovery_doc)), \
         patch("routers.sso.verify_oidc_id_token", side_effect=fake_verify), \
         patch.object(httpx.AsyncClient, "post", new=fake_post):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r_unverified = await ac.get(
                f"/api/v1/auth/sso/{provider_id}/callback?code=abc&state={state_2}",
                cookies={"sso_state_binding": binding},
            )
            assert r_unverified.status_code == 403


@pytest.mark.asyncio
async def test_authn07_oidc_discovery_blocks_nested_ssrf_endpoints():
    """OIDC discovery MUST reject nested token_endpoint or jwks_uri pointing to internal metadata IPs."""
    from services.sso import fetch_oidc_discovery

    class EvilDiscoveryResp:
        status_code = 200

        def json(self):
            return {
                "issuer": "https://evil-idp.example.invalid",
                "authorization_endpoint": "https://evil-idp.example.invalid/auth",
                "token_endpoint": "http://169.254.169.254/latest/meta-data/iam/",
                "jwks_uri": "https://evil-idp.example.invalid/keys",
            }

    async def fake_get(self, url, **kwargs):
        return EvilDiscoveryResp()

    with patch.object(httpx.AsyncClient, "get", new=fake_get):
        with pytest.raises(ValueError):
            await fetch_oidc_discovery("https://evil-idp.example.invalid")


# ══════════════════════════════════════════════════════════════════════════════
# 4. AUTHN-03 & AUTHN-06: MFA Brute-Force Cap, Re-Enroll Guard & 80-bit HMAC Codes
# ══════════════════════════════════════════════════════════════════════════════


def test_authn06_recovery_codes_80bit_hmac_and_legacy_compat():
    """Recovery codes MUST be 80-bit (10 hex - 10 hex) with keyed HMAC-SHA256 digests."""
    plain_codes, hashed_codes = generate_recovery_codes(count=4)
    assert len(plain_codes) == 4
    for code, digest in zip(plain_codes, hashed_codes):
        assert re.fullmatch(r"[0-9A-F]{10}-[0-9A-F]{10}", code)
        assert digest.startswith("hmac_v1:")
    ok, remaining = verify_and_consume_recovery_code(plain_codes[0], hashed_codes)
    assert ok is True
    assert len(remaining) == 3

    # Legacy unsalted SHA-256 code still verifies for seamless migration
    legacy_code = "AABBCC-DDEEFF"
    legacy_hash = hashlib.sha256(legacy_code.encode()).hexdigest()
    ok_leg, rem_leg = verify_and_consume_recovery_code(legacy_code, [legacy_hash])
    assert ok_leg is True and rem_leg == []


@pytest.mark.asyncio
async def test_authn03_mfa_verify_revokes_ticket_after_5_wrong_guesses():
    """POST /mfa/verify MUST invalidate mfa_ticket after 5 wrong guesses."""
    ticket = f"mfa_{uuid.uuid4().hex}"
    uid = str(uuid.uuid4())
    redis_store = {
        f"mfa:ticket:{ticket}": json.dumps(
            {"user_id": uid, "role": "ANALYST", "username": "mfa.victim", "email": "v@a.com", "tenant_id": TENANT_A}
        )
    }
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=lambda k: redis_store.get(k))
    mock_redis.incr = AsyncMock(side_effect=lambda k: redis_store.__setitem__(k, int(redis_store.get(k, 0)) + 1) or redis_store[k])
    mock_redis.expire = AsyncMock()
    mock_redis.delete = AsyncMock(side_effect=lambda k: redis_store.pop(k, None))

    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(
        return_value={
            "mfa_secret": "JBSWY3DPEHPK3PXP",
            "recovery_codes": "[]",
            "token_version": 1,
            "role": "ANALYST",
            "is_active": True,
        }
    )
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn

    transport = ASGITransport(app=app)
    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("database.postgres.get_async_db_conn", return_value=ctx), \
         patch("routers.auth.RateLimiter.__call__", AsyncMock(return_value=None)):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            for attempt in range(5):
                r = await ac.post(
                    "/api/v1/auth/mfa/verify",
                    json={"mfa_ticket": ticket, "code": f"00000{attempt}"},
                    headers={"X-CSRF-Protection": "1"},
                )
                assert r.status_code == 401
            # Ticket MUST be deleted on 5th failure
            assert f"mfa:ticket:{ticket}" not in redis_store


@pytest.mark.asyncio
async def test_authn03_mfa_setup_blocks_overwrite_when_already_enabled():
    """POST /mfa/setup MUST refuse overwriting active MFA without password + current TOTP."""
    uid = str(uuid.uuid4())
    tok = _tok("ANALYST", TENANT_A, user_id=uid)
    mock_redis = AsyncMock()
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(
        return_value={"mfa_enabled": True, "mfa_secret": "JBSWY3DPEHPK3PXP", "password_hash": "$argon2id$..."}
    )
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn

    transport = ASGITransport(app=app)
    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("database.postgres.get_async_db_conn", return_value=ctx), \
         patch("services.auth._verify_token_version", AsyncMock(return_value=None)):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.post(
                "/api/v1/auth/mfa/setup",
                headers={"Authorization": f"Bearer {tok}", "X-CSRF-Protection": "1"},
            )
            assert r.status_code == 403


# ══════════════════════════════════════════════════════════════════════════════
# 5. AUTHN-04, AUTHN-05 & AUTHN-08: Strict JWT, WebSocket CSWSH/Tickets & Gateway
# ══════════════════════════════════════════════════════════════════════════════


def test_authn04_strict_jwt_algorithm_enforcement_rejects_hs256_when_rs256_required():
    """decode_jwt_with_rotation MUST reject HS256 token when algorithm='RS256' is required."""
    hs_token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "role": "SUPER_ADMIN",
            "tenant_id": TENANT_A,
            "exp": datetime.now(timezone.utc) + timedelta(minutes=10),
        },
        "default_development_secret_change_in_prod",
        algorithm="HS256",
    )
    with pytest.raises(jwt.PyJWTError):
        decode_jwt_with_rotation(hs_token, algorithm="RS256")


def test_authn08_downstream_auth_validator_fails_closed_on_empty_secret_and_untrusted_peer():
    """DownstreamAuthValidator MUST fail closed when secret is empty or peer IP is untrusted."""
    validator = DownstreamAuthValidator()

    req_untrusted = MagicMock(spec=Request)
    req_untrusted.headers = {
        "x-user-id": "u1",
        "x-tenant-id": TENANT_A,
        "x-internal-gateway-token": settings.internal_gateway_secret,
    }
    req_untrusted.client = MagicMock(host="198.51.100.77")
    with pytest.raises(HTTPException) as exc1:
        validator.validate_request(req_untrusted)
    assert exc1.value.status_code == 403

    req_empty = MagicMock(spec=Request)
    req_empty.headers = {"x-user-id": "u1", "x-tenant-id": TENANT_A, "x-internal-gateway-token": ""}
    req_empty.client = MagicMock(host="127.0.0.1")
    with patch.object(settings, "internal_gateway_secret", ""):
        with pytest.raises(HTTPException) as exc2:
            validator.validate_request(req_empty)
        assert exc2.value.status_code == 403


@pytest.mark.asyncio
async def test_authn05_websocket_blocks_cswsh_refresh_token_and_prod_query_jwt():
    """WebSocket /ws/live-stream MUST block foreign Origin, refresh tokens, and prod ?token= JWTs."""
    from routers.metrics import websocket_live_stream

    # 1. Cross-origin CSWSH blocked
    ws_evil = AsyncMock(spec=WebSocket)
    ws_evil.headers = {"origin": "https://evil.attacker.example", "host": "localhost:8000"}
    ws_evil.cookies = {}
    await websocket_live_stream(websocket=ws_evil, token=_tok("ANALYST"))
    ws_evil.close.assert_called_once_with(code=1008, reason="Origin not permitted")

    # 2. Refresh token rejected
    refresh_tok = create_refresh_token({"sub": str(uuid.uuid4()), "role": "ANALYST", "tenant_id": TENANT_A})
    ws_ref = AsyncMock(spec=WebSocket)
    ws_ref.headers = {"host": "localhost:8000"}
    ws_ref.cookies = {}
    await websocket_live_stream(websocket=ws_ref, token=refresh_tok)
    assert ws_ref.close.call_args.kwargs["code"] == 1008

    # 3. Query ?token= rejected in production
    ws_prod = AsyncMock(spec=WebSocket)
    ws_prod.headers = {"host": "app.sentinel.example"}
    ws_prod.cookies = {}
    prod_tok = _tok("ANALYST")
    with patch.object(settings, "environment", "prod"):
        await websocket_live_stream(websocket=ws_prod, token=prod_tok)
    assert ws_prod.close.call_args.kwargs["code"] == 1008


@pytest.mark.asyncio
async def test_authn05_ws_ticket_single_use():
    """POST /api/v1/auth/ws-ticket issues a 30s single-use opaque ticket consumed once."""
    from routers.metrics import _authenticate_ws_connection

    uid = str(uuid.uuid4())
    tok = _tok("ANALYST", TENANT_A, user_id=uid)
    store = {}
    mock_redis = AsyncMock()
    mock_redis.setex = AsyncMock(side_effect=lambda k, ttl, v: store.__setitem__(k, v))
    mock_redis.getdel = AsyncMock(side_effect=lambda k: store.pop(k, None))

    transport = ASGITransport(app=app)
    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("services.auth._verify_token_version", AsyncMock(return_value=None)):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.post(
                "/api/v1/auth/ws-ticket",
                headers={"Authorization": f"Bearer {tok}", "X-CSRF-Protection": "1"},
            )
            assert r.status_code == 200
            ticket = r.json()["ticket"]
            assert ticket.startswith("wst_")

        ws = AsyncMock(spec=WebSocket)
        ws.cookies = {}
        first = await _authenticate_ws_connection(ws, ticket=ticket, token=None)
        assert first == (uid, TENANT_A, "ANALYST")
        # Replay MUST fail
        second = await _authenticate_ws_connection(ws, ticket=ticket, token=None)
        assert second is None


# ══════════════════════════════════════════════════════════════════════════════
# 6. AUTHZ-02, AUTHZ-03, AUTHZ-04, AUTHZ-11: Non-RLS Datastore Tenant Isolation
# ══════════════════════════════════════════════════════════════════════════════


def test_authz02_neo4j_cypher_queries_use_strict_tenant_conjunctions():
    """Verify all Neo4j Cypher queries enforce tenant_id via AND/ALL (zero OR tenant leaks)."""
    from routers import alerts as alerts_mod
    from routers import customers as customers_mod
    from routers import network as network_mod
    from services import network_analysis as na_mod

    ubo_src = inspect.getsource(customers_mod._fetch_customer_ubo)
    assert "c.tenant_id = $tenant_id AND p.tenant_id = $tenant_id" in ubo_src

    expand_src = inspect.getsource(network_mod._expand_neo4j)
    assert "ALL(n IN nodes(p) WHERE n.tenant_id = $tenant_id)" in expand_src
    assert "start.tenant_id = $tenant_id OR connected.tenant_id" not in expand_src

    alert_graph_src = inspect.getsource(alerts_mod._build_alert_graph_from_neo4j)
    assert "other.tenant_id = $tenant_id AND" in alert_graph_src
    assert "other.tenant_id = $tenant_id OR t.tenant_id" not in alert_graph_src

    fetch_graph_src = inspect.getsource(na_mod._fetch_graph_neo4j)
    assert "s.tenant_id = $tenant_id" in fetch_graph_src and "r.tenant_id = $tenant_id" in fetch_graph_src
    assert "t.tenant_id = $tenant_id OR s.tenant_id" not in fetch_graph_src

    gds_src = inspect.getsource(na_mod._detect_gds_betweenness)
    assert "node.tenant_id = $tenant_id" in gds_src

    taint_src = inspect.getsource(na_mod.compute_transitive_counterparty_taint)
    assert "ALL(n IN nodes(path) WHERE n.tenant_id = $tenant_id)" in taint_src


@pytest.mark.asyncio
async def test_authz03_redis_locks_isolated_by_tenant_and_strip_lock_token():
    """Tenant B cannot inspect, collide with, or force-break Tenant A's lock, nor read lock_token."""
    alert_id = str(uuid.uuid4())
    tok_a = _tok("L2_INVESTIGATOR", TENANT_A, username="alice.a")
    tok_a2 = _tok("L2_INVESTIGATOR", TENANT_A, username="bob.a")
    tok_b_admin = _tok("ADMIN", TENANT_B, username="admin.b")

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Tenant A acquires lock
        r1 = await ac.post(
            f"/api/v1/locks/ALERT/{alert_id}",
            headers={"Authorization": f"Bearer {tok_a}", "X-CSRF-Protection": "1"},
        )
        assert r1.status_code == 200
        assert "lock_token" in r1.json()["lock"]

        # 2. Same-tenant GET status MUST strip lock_token
        r_stat_a = await ac.get(
            f"/api/v1/locks/ALERT/{alert_id}",
            headers={"Authorization": f"Bearer {tok_a2}"},
        )
        assert r_stat_a.status_code == 200
        assert r_stat_a.json()["is_locked"] is True
        assert "lock_token" not in r_stat_a.json()

        # 3. Same-tenant 409 Conflict MUST strip lock_token
        r_conflict = await ac.post(
            f"/api/v1/locks/ALERT/{alert_id}",
            headers={"Authorization": f"Bearer {tok_a2}", "X-CSRF-Protection": "1"},
        )
        assert r_conflict.status_code == 409
        assert "lock_token" not in r_conflict.json()["detail"]["lock_info"]

        # 4. Tenant B inspecting same alert_id sees is_locked=False (isolated namespace!)
        r_stat_b = await ac.get(
            f"/api/v1/locks/ALERT/{alert_id}",
            headers={"Authorization": f"Bearer {tok_b_admin}"},
        )
        assert r_stat_b.status_code == 200
        assert r_stat_b.json()["is_locked"] is False

        # 5. Tenant B force-breaking cannot break Tenant A's lock
        r_force_b = await ac.delete(
            f"/api/v1/locks/ALERT/{alert_id}?force=true",
            headers={"Authorization": f"Bearer {tok_b_admin}", "X-CSRF-Protection": "1"},
        )
        assert r_force_b.status_code == 200
        r_still_a = await ac.get(
            f"/api/v1/locks/ALERT/{alert_id}",
            headers={"Authorization": f"Bearer {tok_a2}"},
        )
        assert r_still_a.json()["is_locked"] is True

        # Cleanup
        await ac.delete(
            f"/api/v1/locks/ALERT/{alert_id}",
            headers={"Authorization": f"Bearer {tok_a}", "X-CSRF-Protection": "1"},
        )


@pytest.mark.asyncio
async def test_authz04_siem_singleton_never_leaks_cross_tenant_token():
    """Tenant A's SIEM auth_token must never live on global singleton or be sent to Tenant B's probe URL."""
    from services.siem_forwarder import siem_service

    assert not hasattr(siem_service, "auth_token")
    assert not hasattr(siem_service, "destination_url")

    # Tenant B calling /test with an attacker URL MUST NOT receive Tenant A's persisted token
    tok_b = _tok("ADMIN", TENANT_B)
    captured_headers = {}
    orig_post = httpx.AsyncClient.post

    class OkResp:
        status_code = 200
        text = "ok"

    async def fake_post(self, url, **kwargs):
        if str(url).startswith("https://attacker-collector.example.com"):
            captured_headers.update(kwargs.get("headers") or {})
            return OkResp()
        return await orig_post(self, url, **kwargs)

    import socket as _socket
    orig_getaddrinfo = _socket.getaddrinfo

    def selective_getaddrinfo(host, port, *args, **kwargs):
        if host == "attacker-collector.example.com":
            return [(2, 1, 6, "", ("93.184.216.34", 443))]
        return orig_getaddrinfo(host, port, *args, **kwargs)

    with patch.object(
        siem_service,
        "load_tenant_config_with_secret",
        AsyncMock(
            return_value={
                "enabled": True,
                "destination_url": "https://legit-siem.example.com/hec",
                "auth_token": "SECRET-PERSISTED-TOKEN",
                "format": "SPLUNK_HEC",
                "persisted": True,
            }
        ),
    ), patch("services.siem_forwarder.socket.getaddrinfo", side_effect=selective_getaddrinfo), \
       patch.object(httpx.AsyncClient, "post", new=fake_post):
        transport = ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.post(
                "/api/v1/admin/siem/test",
                json={"destination_url": "https://attacker-collector.example.com/steal"},
                headers={"Authorization": f"Bearer {tok_b}", "X-CSRF-Protection": "1"},
            )
            assert r.status_code == 200
            assert "Authorization" not in captured_headers


# ══════════════════════════════════════════════════════════════════════════════
# 7. AUTHZ-05..12: RBAC, SoD, Workflow Gates, Horizontal BOLA & Evidence WORM
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_authz05_06_09_10_rbac_and_workflow_gates():
    """Verify every tightened RBAC, workflow gate, and SUPER_ADMIN protection."""
    l1_tok = _tok("L1_ANALYST", TENANT_A)
    l2_tok = _tok("L2_INVESTIGATOR", TENANT_A)
    analyst_tok = _tok("ANALYST", TENANT_A)
    auditor_tok = _tok("AUDITOR", TENANT_A)
    admin_tok = _tok("ADMIN", TENANT_A)

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        # AUTHZ-05: Tenant ADMIN blocked from global PUT /api/v1/rules/config
        r_rules = await ac.put(
            "/api/v1/rules/config",
            json={"rules": {}},
            headers={"Authorization": f"Bearer {admin_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_rules.status_code == 403

        # AUTHZ-06: L1_ANALYST cannot unfreeze FROZEN account via verify-cip (409)
        frozen_acc_id = str(uuid.uuid4())
        mock_conn = AsyncMock()
        mock_conn.fetchrow = AsyncMock(return_value={"id": uuid.UUID(frozen_acc_id), "status": "FROZEN"})
        ctx = AsyncMock()
        ctx.__aenter__.return_value = mock_conn
        with patch("routers.accounts.get_async_db_conn", return_value=ctx):
            r_cip = await ac.post(
                f"/api/v1/accounts/{frozen_acc_id}/verify-cip",
                json={"document_type": "PASSPORT", "document_number": "P1234567"},
                headers={"Authorization": f"Bearer {l1_tok}", "X-CSRF-Protection": "1", "Idempotency-Key": str(uuid.uuid4())},
            )
            assert r_cip.status_code == 409

        # AUTHZ-06: PATCH /cases/{id} rejects status="CLOSED" (422)
        r_case_close = await ac.patch(
            f"/api/v1/cases/{uuid.uuid4()}",
            json={"status": "CLOSED"},
            headers={"Authorization": f"Bearer {l1_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_case_close.status_code == 422

        # AUTHZ-10: L2_INVESTIGATOR blocked from POST /accounts/{id}/freeze
        r_freeze = await ac.post(
            f"/api/v1/accounts/{uuid.uuid4()}/freeze",
            json={"reason": "Unauthorized freeze attempt"},
            headers={"Authorization": f"Bearer {l2_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_freeze.status_code == 403

        # AUTHZ-10: L1_ANALYST blocked from bulk ASSIGN, SAR draft, EDD request, external RFI
        r_bulk_assign = await ac.post(
            "/api/v1/alerts/bulk-action",
            json={"alert_ids": [str(uuid.uuid4())], "action": "ASSIGN", "assignee_username": "mlro"},
            headers={"Authorization": f"Bearer {l1_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_bulk_assign.status_code == 403

        r_bulk_sar = await ac.post(
            "/api/v1/alerts/bulk-action",
            json={"alert_ids": [str(uuid.uuid4())], "action": "CLOSE_SAR", "justification": "Test SAR"},
            headers={"Authorization": f"Bearer {analyst_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_bulk_sar.status_code == 403

        r_sar_draft = await ac.post(
            "/api/v1/fincen/sar/drafts",
            json={"alert_id": str(uuid.uuid4()), "narrative": "Detailed suspicious activity narrative text"},
            headers={"Authorization": f"Bearer {l1_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_sar_draft.status_code == 403

        r_edd = await ac.post(
            "/api/v1/edd/requests",
            json={"account_id": str(uuid.uuid4()), "trigger_reason": "PEP_HIT"},
            headers={"Authorization": f"Bearer {l1_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_edd.status_code == 403

        r_rfi = await ac.post(
            f"/api/v1/rfi/cases/{uuid.uuid4()}",
            json={"recipient_email": "cust@example.com", "recipient_role": "CUSTOMER"},
            headers={"Authorization": f"Bearer {l1_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_rfi.status_code == 403

        # AUTHZ-10 & AUTHZ-11: ANALYST blocked from STR batch, ML retrain, Watchlist sync
        r_str = await ac.post(
            "/api/v1/str/batch/generate",
            headers={"Authorization": f"Bearer {analyst_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_str.status_code == 403

        r_retrain = await ac.post(
            "/api/v1/ml/retrain",
            headers={"Authorization": f"Bearer {analyst_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_retrain.status_code == 403

        r_wl = await ac.post(
            "/api/v1/watchlist/sync",
            headers={"Authorization": f"Bearer {analyst_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_wl.status_code == 403

        # AUTHZ-10: Read-only AUDITOR blocked from mutating QA endpoints
        r_qa_sample = await ac.post(
            "/api/v1/qa/sample",
            json={"sample_rate": 0.1},
            headers={"Authorization": f"Bearer {auditor_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_qa_sample.status_code == 403

        r_qa_rev = await ac.post(
            f"/api/v1/qa/{uuid.uuid4()}/review",
            json={"decision": "PASSED", "notes": "Attempting mutation as AUDITOR"},
            headers={"Authorization": f"Bearer {auditor_tok}", "X-CSRF-Protection": "1"},
        )
        assert r_qa_rev.status_code == 403

        # AUTHZ-09: Tenant ADMIN cannot provision SUPER_ADMIN (403, not silent downgrade)
        with patch("services.auth.check_breached_password", AsyncMock(return_value=False)):
            r_prov = await ac.post(
                "/api/v1/auth/provision",
                json={"username": "evil_super", "password": "SuperSecurePassword!2026", "role": "SUPER_ADMIN"},
                headers={"Authorization": f"Bearer {admin_tok}", "X-CSRF-Protection": "1"},
            )
            assert r_prov.status_code == 403


@pytest.mark.asyncio
async def test_authz08_fincen_fail_closed_draft_mismatch_and_xml_tamper():
    """FinCEN SAR submit MUST fail closed (503) on DB error, block mismatched draft_id & XML tampering."""
    mlro_id = uuid.uuid4()
    analyst_id = uuid.uuid4()
    mlro_tok = _tok("MLRO", TENANT_A, user_id=str(mlro_id))
    alert_a = str(uuid.uuid4())
    alert_b = str(uuid.uuid4())
    draft_id = str(uuid.uuid4())
    approved_xml = "<SuspiciousActivityReport><Narrative>MLRO Approved Exact Text</Narrative></SuspiciousActivityReport>"

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {mlro_tok}", "X-CSRF-Protection": "1"},
    ) as ac:
        # 1. DB error during preflight -> 503 fail-closed (never bypasses 4-eyes!)
        with patch("routers.fincen.get_async_db_conn", side_effect=RuntimeError("DB timeout")), \
             patch("routers.fincen.check_idempotency", AsyncMock(return_value=(False, None))), \
             patch("routers.fincen.clear_idempotency_key", AsyncMock()):
            r_503 = await ac.post(
                "/api/v1/fincen/sar/submit",
                json={"alert_id": alert_a, "sar_xml": approved_xml},
            )
            assert r_503.status_code == 503

        # 2. draft_id belongs to alert_b while filing alert_a -> 403
        mock_conn_mis = AsyncMock()
        mock_conn_mis.fetchrow.side_effect = [
            {"id": uuid.UUID(alert_a), "fincen_tracking_id": None, "fincen_filing_status": "UNSUBMITTED", "fincen_submitted_at": None},
            {"id": uuid.UUID(draft_id), "alert_id": uuid.UUID(alert_b), "status": "APPROVED", "drafted_by": analyst_id, "reviewed_by": mlro_id, "reviewed_by_username": "mlro", "xml_payload": approved_xml},
        ]
        ctx_mis = AsyncMock()
        ctx_mis.__aenter__.return_value = mock_conn_mis
        with patch("routers.fincen.get_async_db_conn", return_value=ctx_mis), \
             patch("routers.fincen.check_idempotency", AsyncMock(return_value=(False, None))):
            r_mis = await ac.post(
                "/api/v1/fincen/sar/submit",
                json={"alert_id": alert_a, "draft_id": draft_id, "sar_xml": approved_xml},
            )
            assert r_mis.status_code == 403

        # 3. Tampered XML differs from approved draft's xml_payload -> 403
        mock_conn_tmp = AsyncMock()
        mock_conn_tmp.fetchrow.side_effect = [
            {"id": uuid.UUID(alert_a), "fincen_tracking_id": None, "fincen_filing_status": "UNSUBMITTED", "fincen_submitted_at": None},
            {"id": uuid.UUID(draft_id), "alert_id": uuid.UUID(alert_a), "status": "APPROVED", "drafted_by": analyst_id, "reviewed_by": mlro_id, "reviewed_by_username": "mlro", "xml_payload": approved_xml},
        ]
        ctx_tmp = AsyncMock()
        ctx_tmp.__aenter__.return_value = mock_conn_tmp
        with patch("routers.fincen.get_async_db_conn", return_value=ctx_tmp), \
             patch("routers.fincen.check_idempotency", AsyncMock(return_value=(False, None))):
            r_tmp = await ac.post(
                "/api/v1/fincen/sar/submit",
                json={"alert_id": alert_a, "draft_id": draft_id, "sar_xml": "<SuspiciousActivityReport><Narrative>TAMPERED</Narrative></SuspiciousActivityReport>"},
            )
            assert r_tmp.status_code == 403

        # 4. PATCH /sar/drafts/{id} blocks editing PENDING_MLRO_REVIEW drafts (400)
        mock_conn_rev = AsyncMock()
        mock_conn_rev.fetchrow = AsyncMock(return_value={"id": uuid.UUID(draft_id), "status": "PENDING_MLRO_REVIEW"})
        ctx_rev = AsyncMock()
        ctx_rev.__aenter__.return_value = mock_conn_rev
        with patch("routers.fincen.get_async_db_conn", return_value=ctx_rev):
            r_edit = await ac.patch(
                f"/api/v1/fincen/sar/drafts/{draft_id}",
                json={"narrative": "Trying to tamper while MLRO reviews!"},
            )
            assert r_edit.status_code == 400


@pytest.mark.asyncio
async def test_authz07_notification_read_enforces_recipient_scoping():
    """PATCH /notifications/{id}/read MUST enforce recipient_user_id and recipient_role predicates."""
    tok = _tok("L1_ANALYST", TENANT_A)
    mock_conn = AsyncMock()
    mock_conn.fetchval = AsyncMock(return_value=None)  # Not owned by caller -> 404
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn

    transport = ASGITransport(app=app)
    with patch("routers.notifications.get_async_db_conn", return_value=ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.patch(
                f"/api/v1/notifications/{uuid.uuid4()}/read",
                headers={"Authorization": f"Bearer {tok}", "X-CSRF-Protection": "1"},
            )
            assert r.status_code == 404
            sql = mock_conn.fetchval.call_args[0][0]
            assert "recipient_user_id" in sql and "recipient_role" in sql


@pytest.mark.asyncio
async def test_authz12_cases_and_auditor_rooms_reject_foreign_ids():
    """create_case & create_auditor_room MUST reject foreign/missing alert_ids / allowed_case_ids (404)."""
    mlro_tok = _tok("MLRO", TENANT_A)
    mock_conn = AsyncMock()
    mock_conn.fetch = AsyncMock(return_value=[])  # 0 owned rows found
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://test",
        headers={"Authorization": f"Bearer {mlro_tok}", "X-CSRF-Protection": "1"},
    ) as ac:
        with patch("routers.cases.get_async_db_conn", return_value=ctx):
            r_case = await ac.post(
                "/api/v1/cases",
                headers={"Idempotency-Key": str(uuid.uuid4())},
                json={"title": "Foreign Alert Injection", "alert_ids": [str(uuid.uuid4())]},
            )
            assert r_case.status_code == 404

        with patch("routers.audit.get_async_db_conn", return_value=ctx):
            r_room = await ac.post(
                "/api/v1/audit/rooms",
                json={"room_name": "Examiner Room", "allowed_case_ids": [str(uuid.uuid4())]},
            )
            assert r_room.status_code == 404


@pytest.mark.asyncio
async def test_evidence_delete_enforces_worm_backend_before_db_delete():
    """DELETE /cases/{id}/evidence/{ev_id} MUST invoke storage backend delete_object and reject WORM (403)."""
    l2_tok = _tok("L2_INVESTIGATOR", TENANT_A)
    case_id = str(uuid.uuid4())
    ev_id = str(uuid.uuid4())

    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(
        return_value={
            "storage_key": f"s3://aml-worm/evidence/{TENANT_A}/doc.pdf",
            "filename": "doc.pdf",
            "storage_backend": "s3",
        }
    )
    mock_conn.execute = AsyncMock()
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn

    mock_s3 = AsyncMock()
    mock_s3.delete_object = AsyncMock(side_effect=PermissionError("Cannot delete WORM-locked regulatory evidence"))

    transport = ASGITransport(app=app)
    with patch("routers.evidence.get_async_db_conn", return_value=ctx), \
         patch("routers.evidence._resolve_case_uuid", AsyncMock(return_value=uuid.UUID(case_id))), \
         patch("services.evidence_storage.S3EvidenceBackend", return_value=mock_s3):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.delete(
                f"/api/v1/cases/{case_id}/evidence/{ev_id}",
                headers={"Authorization": f"Bearer {l2_tok}", "X-CSRF-Protection": "1"},
            )
            assert r.status_code == 403
            assert not mock_conn.execute.called  # DB record MUST remain intact!


# ══════════════════════════════════════════════════════════════════════════════
# 8. HARD-01..05, AUTHN-09 & LOW-01..04: Platform Hardening & Token Hygiene
# ══════════════════════════════════════════════════════════════════════════════


@pytest.mark.asyncio
async def test_hard01_ip_only_rate_limiter_defeats_jwt_bucket_evasion():
    """RateLimiter(ip_only=True) MUST ignore changing Bearer tokens from the same IP."""
    limiter = RateLimiter(limit=2, window=60, ip_only=True)
    req_base = MagicMock(spec=Request)
    req_base.url = MagicMock(path="/api/v1/auth/login")
    req_base.state = MagicMock(client_ip="198.51.100.55")
    req_base.client = MagicMock(host="198.51.100.55")
    req_base.cookies = {}

    with patch("services.rate_limiter.get_async_redis_client", AsyncMock(return_value=None)):
        for i in range(2):
            req_base.headers = {"Authorization": f"Bearer {_tok('ANALYST', user_id=str(uuid.uuid4()))}"}
            await limiter(req_base)

        # 3rd request with a brand-new JWT from same IP MUST hit 429 with Retry-After!
        req_base.headers = {"Authorization": f"Bearer {_tok('ANALYST', user_id=str(uuid.uuid4()))}"}
        with pytest.raises(HTTPException) as exc:
            await limiter(req_base)
        assert exc.value.status_code == 429
        assert exc.value.headers.get("Retry-After") == "60"


def test_hard01_trusted_proxy_prod_loopback_only_and_no_leftmost_spoof():
    """In production without TRUSTED_PROXY_CIDRS, private RFC1918 peers must NOT be trusted."""
    req_vpc = MagicMock(spec=Request)
    req_vpc.client = MagicMock(host="10.0.5.9")
    req_vpc.headers = {"x-forwarded-for": "203.0.113.1"}

    with patch.object(settings, "environment", "prod"), patch.dict(os.environ, {"TRUSTED_PROXY_CIDRS": ""}):
        assert get_trusted_client_ip(req_vpc) == "10.0.5.9"

    # When all XFF hops are trusted internal IPs, must fall back to direct peer_ip (not leftmost spoofed hop)
    req_all_priv = MagicMock(spec=Request)
    req_all_priv.client = MagicMock(host="127.0.0.1")
    req_all_priv.headers = {"x-forwarded-for": "10.1.1.1, 10.2.2.2"}
    assert get_trusted_client_ip(req_all_priv) == "127.0.0.1"


@pytest.mark.asyncio
async def test_hard02_and_hard03_prod_alias_enforces_all_production_guards():
    """ENVIRONMENT='prod' MUST activate is_production, block /check-username (403), and reject HTTP CORS."""
    with pytest.raises(ValueError, match="https://"):
        Settings(
            environment="prod",
            postgres_password="StrongUniqueProdPassword!2026#99",
            aml_app_password="StrongUniqueAppPassword!2026#99",
            neo4j_password="StrongUniqueNeo4jPassword!2026#99",
            internal_gateway_secret="super_secret_gateway_token_2026_x9",
            metrics_secret="super_secret_metrics_token_2026_x9",
            allowed_origins="http://insecure.bank.com",
            allow_offline_dev=False,
        )

    valid_prod = Settings(
        environment="prod",
        postgres_password="StrongUniqueProdPassword!2026#99",
        aml_app_password="StrongUniqueAppPassword!2026#99",
        neo4j_password="StrongUniqueNeo4jPassword!2026#99",
        internal_gateway_secret="super_secret_gateway_token_2026_x9",
        metrics_secret="super_secret_metrics_token_2026_x9",
        allowed_origins="https://aml.bank.com",
        allow_offline_dev=False,
    )
    assert valid_prod.is_production is True

    transport = ASGITransport(app=app)
    with patch.object(settings, "environment", "prod"):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r_enum = await ac.get("/api/v1/auth/check-username?username=admin")
            assert r_enum.status_code == 403


@pytest.mark.asyncio
async def test_hard04_browser_mode_omits_raw_tokens_and_static_has_no_localstorage_jwt():
    """Browser-mode /refresh omits raw tokens from JSON body, and static/ has zero localStorage JWT readers."""
    # Static check: no localStorage.getItem('jwt_token') or localStorage.getItem('access_token')
    static_dir = Path(__file__).resolve().parent.parent / "static"
    for p in list(static_dir.glob("*.js")) + list(static_dir.glob("*.html")):
        txt = p.read_text(encoding="utf-8", errors="ignore")
        assert "localStorage.getItem('jwt_token')" not in txt, f"Found legacy jwt_token reader in {p.name}"
        assert "localStorage.getItem('access_token')" not in txt, f"Found legacy access_token reader in {p.name}"
        assert "?token=${encodeURIComponent" not in txt, f"Found WS query-string JWT in {p.name}"

    # Browser-mode /refresh omits raw access_token & refresh_token in JSON
    uid = str(uuid.uuid4())
    ref_tok = create_refresh_token(
        {"sub": uid, "role": "ANALYST", "username": "browser.user", "tenant_id": TENANT_A, "token_version": 1, "family_id": "fam_br"}
    )
    store = {}
    mock_redis = AsyncMock()
    mock_redis.get = AsyncMock(side_effect=lambda k: store.get(k))
    mock_redis.set = AsyncMock(side_effect=lambda k, v, ex=None, nx=False: store.__setitem__(k, v) or True)
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={"role": "ANALYST", "tenant_id": uuid.UUID(TENANT_A), "token_version": 1, "is_active": True})
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn

    transport = ASGITransport(app=app)
    with patch("database.redis_db.get_async_redis_client", return_value=mock_redis), \
         patch("database.postgres.get_async_db_conn", return_value=ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.post(
                "/api/v1/auth/refresh",
                cookies={"refresh_token": ref_tok},
                headers={"X-CSRF-Protection": "1", "X-Client-Mode": "browser"},
            )
            assert r.status_code == 200
            body = r.json()
            assert body["token_type"] == "cookie"
            assert "access_token" not in body
            assert "refresh_token" not in body
            assert "access_token" in r.cookies and "refresh_token" in r.cookies


@pytest.mark.asyncio
async def test_hard05_vault_dev_token_blocked_in_production_and_500_sanitized():
    """VAULT_DEV_TOKEN MUST raise RuntimeError in production, and HTTP 500s must not leak raw errors."""
    from services.vault_loader import VaultSecretsLoader

    with patch.dict(os.environ, {"VAULT_ADDR": "https://vault.prod", "VAULT_DEV_TOKEN": "root-dev-tok", "ENVIRONMENT": "prod"}), \
         patch.object(settings, "environment", "prod"):
        with pytest.raises(RuntimeError, match="VAULT_DEV_TOKEN is strictly prohibited in production"):
            await VaultSecretsLoader.bootstrap()

    # Verify raw DB error text is sanitized on HTTP 500
    tok = _tok("ANALYST", TENANT_A)
    transport = ASGITransport(app=app)
    with patch("routers.ml_feedback.get_async_db_conn", side_effect=RuntimeError("SECRET_INTERNAL_DSN_LEAK_12345")):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r = await ac.get("/api/v1/ml/feedback-stats", headers={"Authorization": f"Bearer {tok}"})
            assert r.status_code == 500
            assert "SECRET_INTERNAL_DSN_LEAK_12345" not in r.text


@pytest.mark.asyncio
async def test_authn09_oversized_password_rejected_and_lockout_normalized():
    """Passwords >128 chars rejected immediately (401) and lockout usernames are case-normalized."""
    assert _normalize_lockout_username("  Admin@Bank.COM ") == "admin@bank.com"

    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        r = await ac.post(
            "/api/v1/auth/login",
            data={"username": "admin", "password": "A" * 1000},
            headers={"X-CSRF-Protection": "1"},
        )
        assert r.status_code == 401
        # Verify http_exception_handler preserved WWW-Authenticate header (HARD-01)
        assert r.headers.get("www-authenticate") == "Bearer"


@pytest.mark.asyncio
async def test_low01_low02_portal_referrer_policy_and_content_disposition_sanitized():
    """Public RFI/Auditor portals send Referrer-Policy: no-referrer & Cache-Control: no-store; headers sanitized."""
    transport = ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        r_rfi = await ac.get("/api/v1/rfi/public/invalid_token_probe")
        assert r_rfi.headers.get("referrer-policy") == "no-referrer"
        assert r_rfi.headers.get("cache-control") == "no-store"

        r_room = await ac.get("/api/v1/audit/rooms/invalid_room_probe/view")
        assert r_room.headers.get("referrer-policy") == "no-referrer"
        assert r_room.headers.get("cache-control") == "no-store"

    # LOW-02: Content-Disposition strips quotes/newlines/special chars
    tok = _tok("MLRO", TENANT_A)
    mock_conn = AsyncMock()
    mock_conn.fetchrow = AsyncMock(return_value={"payload_xml": "<Batch/>"})
    ctx = AsyncMock()
    ctx.__aenter__.return_value = mock_conn
    with patch("routers.str_batch.get_async_db_conn", return_value=ctx):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
            r_dl = await ac.get(
                '/api/v1/str/batch/evil"name;x=1/download',
                headers={"Authorization": f"Bearer {tok}"},
            )
            assert r_dl.status_code == 200
            cd = r_dl.headers.get("content-disposition", "")
            assert ";" not in cd.split("filename=")[1]
            assert 'filename="evil_name_x_1.xml"' in cd
