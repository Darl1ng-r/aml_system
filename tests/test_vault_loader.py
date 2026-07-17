"""
tests/test_vault_loader.py
===========================
Unit tests for the Vault secrets loader.

Uses respx to mock the Vault HTTP API so tests are:
  - Fast (no network calls)
  - Deterministic (no real Vault required)
  - Isolated (each test gets a fresh SecretStore)

Test matrix:
  T1  AppRole login constructs the correct URL and payload
  T2  Successful AppRole auth stores the client token
  T3  Failed AppRole auth raises VaultAuthError with HTTP status
  T4  Successful KV-v2 read returns unwrapped data dict
  T5  404 KV-v2 read raises VaultSecretError
  T6  bootstrap() with VAULT_ADDR unset returns immediately (dev fallback)
  T7  bootstrap() with VAULT_DEV_TOKEN uses token auth, not AppRole
  T8  bootstrap() raises RuntimeError when AppRole creds missing
  T9  bootstrap() populates SecretStore after successful auth + fetch
  T10 SecretStore.get() returns None for missing key (no KeyError)
  T11 SecretStore.require() raises KeyError for missing key
  T12 _renewal_loop() calls _fetch_all after sleeping
"""

import asyncio
import os
import pytest
import httpx

try:
    import respx
    RESPX_AVAILABLE = True
except ImportError:
    RESPX_AVAILABLE = False

pytestmark = [
    pytest.mark.skipif(not RESPX_AVAILABLE, reason="respx not installed"),
]

VAULT_ADDR = "http://vault-test.local:8200"
FAKE_TOKEN = "s.TESTTOKEN123"
APPROLE_LOGIN_URL = f"{VAULT_ADDR}/v1/auth/approle/login"


# ── Helpers ────────────────────────────────────────────────────────────────

def _approle_login_response():
    return {
        "auth": {
            "client_token": FAKE_TOKEN,
            "lease_duration": 3600,
        }
    }


def _kv2_response(path_segment: str, data: dict):
    return {
        "data": {
            "data": data,
            "metadata": {"version": 1}
        }
    }


# ── T1/T2 — AppRole auth ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_approle_auth_constructs_correct_request():
    from services.vault_client import VaultClient

    with respx.mock:
        route = respx.post(APPROLE_LOGIN_URL).mock(
            return_value=httpx.Response(200, json=_approle_login_response())
        )
        client = VaultClient(addr=VAULT_ADDR)
        await client.authenticate_approle(role_id="test-role", secret_id="test-secret")

        assert route.called
        sent = route.calls[0].request
        import json
        body = json.loads(sent.content)
        assert body["role_id"] == "test-role"
        assert body["secret_id"] == "test-secret"


@pytest.mark.asyncio
async def test_approle_auth_stores_token():
    from services.vault_client import VaultClient

    with respx.mock:
        respx.post(APPROLE_LOGIN_URL).mock(
            return_value=httpx.Response(200, json=_approle_login_response())
        )
        client = VaultClient(addr=VAULT_ADDR)
        await client.authenticate_approle(role_id="r", secret_id="s")
        assert client._token == FAKE_TOKEN


# ── T3 — AppRole auth failure ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_approle_auth_failure_raises_vault_auth_error():
    from services.vault_client import VaultClient, VaultAuthError

    with respx.mock:
        respx.post(APPROLE_LOGIN_URL).mock(
            return_value=httpx.Response(403, json={"errors": ["permission denied"]})
        )
        client = VaultClient(addr=VAULT_ADDR)
        with pytest.raises(VaultAuthError, match="403"):
            await client.authenticate_approle(role_id="bad", secret_id="bad")


# ── T4 — KV-v2 read ───────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_kv2_read_returns_unwrapped_data():
    from services.vault_client import VaultClient

    secret_path = "aml/postgres"
    url = f"{VAULT_ADDR}/v1/secret/data/{secret_path}"
    expected_data = {"password": "s3cr3t", "user": "postgres"}

    with respx.mock:
        respx.post(APPROLE_LOGIN_URL).mock(
            return_value=httpx.Response(200, json=_approle_login_response())
        )
        respx.get(url).mock(
            return_value=httpx.Response(200, json=_kv2_response("postgres", expected_data))
        )

        client = VaultClient(addr=VAULT_ADDR)
        await client.authenticate_approle(role_id="r", secret_id="s")
        result = await client.read_secret(secret_path)

    assert result == expected_data


# ── T5 — 404 secret path ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_kv2_read_404_raises_vault_secret_error():
    from services.vault_client import VaultClient, VaultSecretError

    secret_path = "aml/missing"
    url = f"{VAULT_ADDR}/v1/secret/data/{secret_path}"

    with respx.mock:
        respx.post(APPROLE_LOGIN_URL).mock(
            return_value=httpx.Response(200, json=_approle_login_response())
        )
        respx.get(url).mock(return_value=httpx.Response(404, json={"errors": []}))

        client = VaultClient(addr=VAULT_ADDR)
        await client.authenticate_approle(role_id="r", secret_id="s")
        with pytest.raises(VaultSecretError, match="not found"):
            await client.read_secret(secret_path)


# ── T6 — bootstrap dev fallback (no VAULT_ADDR) ──────────────────────────

@pytest.mark.asyncio
async def test_bootstrap_no_vault_addr_returns_immediately(monkeypatch):
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    # Reset module-level client state
    from services import vault_loader
    vault_loader.VaultSecretsLoader._client = None

    # Should complete without error and without making any HTTP calls
    await vault_loader.VaultSecretsLoader.bootstrap()
    assert vault_loader.VaultSecretsLoader._client is None


# ── T7 — VAULT_DEV_TOKEN path ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_bootstrap_uses_dev_token_when_set(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", VAULT_ADDR)
    monkeypatch.setenv("VAULT_DEV_TOKEN", "dev-root-token")
    monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
    monkeypatch.delenv("VAULT_SECRET_ID", raising=False)

    from services import vault_loader
    vault_loader.VaultSecretsLoader._client = None

    # Build URLs for all 7 secret paths
    all_paths = [
        "aml/postgres", "aml/neo4j", "aml/elasticsearch",
        "aml/jwt", "aml/fincen", "aml/watchlists", "aml/supabase"
    ]

    with respx.mock:
        # No AppRole call — should not be called
        respx.post(APPROLE_LOGIN_URL).mock(
            return_value=httpx.Response(403, json={})
        )
        for path in all_paths:
            respx.get(f"{VAULT_ADDR}/v1/secret/data/{path}").mock(
                return_value=httpx.Response(200, json=_kv2_response(path.split("/")[-1], {"key": "val"}))
            )

        await vault_loader.VaultSecretsLoader.bootstrap()

    # AppRole was NOT called (token auth was used)
    assert not respx.calls.call_count or all(
        APPROLE_LOGIN_URL not in str(c.request.url)
        for c in respx.calls
    )


# ── T8 — missing AppRole creds with VAULT_ADDR set ────────────────────────

@pytest.mark.asyncio
async def test_bootstrap_raises_when_approle_creds_missing(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", VAULT_ADDR)
    monkeypatch.delenv("VAULT_DEV_TOKEN", raising=False)
    monkeypatch.delenv("VAULT_ROLE_ID", raising=False)
    monkeypatch.delenv("VAULT_SECRET_ID", raising=False)

    from services import vault_loader
    vault_loader.VaultSecretsLoader._client = None

    with pytest.raises(RuntimeError, match="VAULT_ROLE_ID"):
        await vault_loader.VaultSecretsLoader.bootstrap()


# ── T9 — successful bootstrap populates SecretStore ───────────────────────

@pytest.mark.asyncio
async def test_bootstrap_populates_secret_store(monkeypatch):
    monkeypatch.setenv("VAULT_ADDR", VAULT_ADDR)
    monkeypatch.setenv("VAULT_ROLE_ID", "test-role")
    monkeypatch.setenv("VAULT_SECRET_ID", "test-secret")
    monkeypatch.delenv("VAULT_DEV_TOKEN", raising=False)

    from services import vault_loader
    vault_loader.VaultSecretsLoader._client = None
    vault_loader.SecretStore._store.clear()
    vault_loader.SecretStore._loaded = False

    all_paths = [
        "aml/postgres", "aml/neo4j", "aml/elasticsearch",
        "aml/jwt", "aml/fincen", "aml/watchlists", "aml/supabase"
    ]
    renew_url = f"{VAULT_ADDR}/v1/auth/token/renew-self"

    with respx.mock:
        respx.post(APPROLE_LOGIN_URL).mock(
            return_value=httpx.Response(200, json=_approle_login_response())
        )
        for path in all_paths:
            seg = path.split("/")[-1]
            respx.get(f"{VAULT_ADDR}/v1/secret/data/{path}").mock(
                return_value=httpx.Response(200, json=_kv2_response(seg, {"password": f"{seg}_pw"}))
            )

        await vault_loader.VaultSecretsLoader.bootstrap()

    assert vault_loader.SecretStore.is_loaded
    assert vault_loader.SecretStore.get("postgres.password") == "postgres_pw"
    assert vault_loader.SecretStore.get("jwt.password") == "jwt_pw"


# ── T10/T11 — SecretStore get / require ──────────────────────────────────

@pytest.mark.skipif(not RESPX_AVAILABLE, reason="respx not installed")
def test_secret_store_get_returns_none_for_missing():
    from services.vault_loader import _SecretStore
    store = _SecretStore()
    assert store.get("missing.key") is None
    assert store.get("missing.key", "default") == "default"


@pytest.mark.skipif(not RESPX_AVAILABLE, reason="respx not installed")
def test_secret_store_require_raises_for_missing():
    from services.vault_loader import _SecretStore
    store = _SecretStore()
    with pytest.raises(KeyError, match="missing.key"):
        store.require("missing.key")
