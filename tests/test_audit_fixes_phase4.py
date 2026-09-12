"""
Phase 4 Regression Tests: 360-Degree Institutional Hardening
=============================================================
Validates:
1. High-throughput keyset cursor pagination in /api/v1/transactions
2. Next cursor header emission (X-Next-Cursor-Timestamp, X-Next-Cursor-ID)
3. Subresource Integrity (SRI) attributes in static/index.html
4. WCAG 2.1 AA accessibility contrast updates in static/style.css
5. Kubernetes Alembic Job and PodDisruptionBudget YAML validity
"""

import pytest
import uuid
from datetime import datetime, timezone
import yaml
from unittest.mock import AsyncMock, patch


@pytest.mark.asyncio
async def test_keyset_cursor_pagination():
    """Verifies that transactions endpoint supports keyset cursor pagination."""
    from httpx import AsyncClient, ASGITransport
    from main import app
    from services.auth import create_access_token

    tenant_id = str(uuid.uuid4())
    token = create_access_token({"sub": "analyst_1", "role": "ANALYST", "tenant_id": tenant_id})
    headers = {"Authorization": f"Bearer {token}"}

    sample_id = uuid.uuid4()
    sample_time = datetime.now(timezone.utc)

    mock_row = {
        "id": sample_id,
        "amount": 12500.0,
        "currency": "USD",
        "status": "APPROVED",
        "timestamp": sample_time,
        "country": "US",
        "channel": "Wire",
        "sender_account": "ACC_SEND_1",
        "sender_name": "Alice Corp",
        "receiver_account": "ACC_RECV_1",
        "receiver_name": "Bob LLC"
    }

    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = [mock_row]
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("routers.transactions.get_async_db_read_conn", return_value=mock_ctx):
        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as ac:
            # Query using cursor timestamp via params
            params = {
                "cursor_timestamp": sample_time.isoformat(),
                "cursor_id": str(sample_id),
                "limit": 10
            }
            resp = await ac.get("/api/v1/transactions", params=params, headers=headers)
            assert resp.status_code == 200
            data = resp.json()
            assert len(data) == 1
            assert data[0]["id"] == str(sample_id)

            # Verify cursor headers
            assert "X-Next-Cursor-Timestamp" in resp.headers
            assert "X-Next-Cursor-ID" in resp.headers
            assert resp.headers["X-Next-Cursor-ID"] == str(sample_id)
            # In cursor mode, total count scan is bypassed
            assert "X-Total-Count" not in resp.headers


def test_subresource_integrity_in_index_html():
    """Verifies that external CDN scripts in index.html have Subresource Integrity attributes."""
    with open("static/index.html", "r", encoding="utf-8") as f:
        html = f.read()

    # Chart.js has integrity attribute
    assert 'cdn.jsdelivr.net/npm/chart.js@4.4.1' in html
    assert 'integrity="sha384-9nhczxUqK87bcKHh20fSQcTGD4qq5GhayNYSYWqwBkINBhOfQLg/P5HG5lF1urn4"' in html

    # Vis-network has integrity attribute
    assert 'unpkg.com/vis-network@10.1.2' in html
    assert 'integrity="sha384-RDdG1CLOxjNlTHh4JYx/rnAueaMHbkBHmeHwrEyljMQw3LF0it4SkuNotIY/FPxD"' in html

    # Accessibility attributes on log feed
    assert 'role="log"' in html
    assert 'aria-live="polite"' in html


def test_wcag_color_contrast_in_style_css():
    """Verifies that --ink-soft is darkened to #4B4F5A for WCAG AA compliance."""
    with open("static/style.css", "r", encoding="utf-8") as f:
        css = f.read()

    assert "--ink-soft:             #4B4F5A;" in css
    assert ":focus-visible" in css


def test_kubernetes_manifests_validity():
    """Verifies that the new Alembic Job and PodDisruptionBudget YAML manifests are syntactically valid."""
    with open("deployments/kubernetes/alembic-migration-job.yaml", "r", encoding="utf-8") as f:
        job = yaml.safe_load(f)
    assert job["kind"] == "Job"
    assert job["metadata"]["name"] == "aml-alembic-migration"
    assert job["spec"]["template"]["spec"]["containers"][0]["command"] == ["alembic", "upgrade", "head"]

    with open("deployments/kubernetes/fastapi-pdb.yaml", "r", encoding="utf-8") as f:
        pdb = yaml.safe_load(f)
    assert pdb["kind"] == "PodDisruptionBudget"
    assert pdb["metadata"]["name"] == "aml-fastapi-pdb"
    assert pdb["spec"]["minAvailable"] == 1
