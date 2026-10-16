import pytest
import uuid
from unittest.mock import patch, AsyncMock, MagicMock
from routers.screening import perform_pep_search


@pytest.mark.anyio
async def test_perform_pep_search_scopes_by_tenant_id():
    """Verify perform_pep_search queries PostgreSQL with tenant_id parameter."""
    tenant_id = "00000000-0000-0000-0000-000000000001"
    t_uuid = uuid.UUID(tenant_id)

    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = [
        {
            "name": "Ivan Petrov",
            "pep_tier": "TIER_2_GOVERNMENT_MINISTER",
            "position": "Minister of Energy",
            "country": "RU",
            "rca_flag": False,
            "source_database": "FATF PEP Register"
        }
    ]

    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    # Simulate ES failure so code falls back to PostgreSQL
    mock_es = AsyncMock()
    mock_es.search.side_effect = Exception("Elasticsearch unavailable")

    with patch("database.postgres.get_async_db_read_conn", return_value=mock_ctx) as mock_get_db:
        res = await perform_pep_search("Ivan Petrov", 0.80, mock_es, tenant_id=tenant_id)

        assert res["match_found"] is True
        assert res["matched_entry"]["name"] == "Ivan Petrov"

        # Verify get_async_db_read_conn was called with tenant_id
        mock_get_db.assert_called_once_with(tenant_id=tenant_id)

        # Verify fetch query passed t_uuid as parameter $1
        mock_conn.fetch.assert_called_once()
        args, kwargs = mock_conn.fetch.call_args
        assert t_uuid in args


@pytest.mark.anyio
async def test_perform_sanctions_search_postgres_and_baseline_fallback():
    """Verify perform_sanctions_search falls back to PostgreSQL when Elasticsearch is offline."""
    from routers.screening import perform_sanctions_search

    mock_es = AsyncMock()
    mock_es.search.side_effect = Exception("Elasticsearch connection refused")

    tenant_id = "00000000-0000-0000-0000-000000000001"
    t_uuid = uuid.UUID(tenant_id)

    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = [
        {
            "name": "V. Smirnov LLC",
            "source_database": "OFAC SDN List",
            "country": "RU"
        }
    ]
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("database.postgres.get_async_db_read_conn", return_value=mock_ctx) as mock_get_db:
        res = await perform_sanctions_search("Vladimir Smirnov", 0.70, mock_es, tenant_id=tenant_id)
        assert res["match_found"] is True
        assert res["score"] >= 0.70
        assert mock_get_db.called


@pytest.mark.anyio
async def test_perform_sanctions_search_baseline_zero_infrastructure():
    """Verify perform_sanctions_search hits built-in sanctions baseline with zero backing infrastructure."""
    from routers.screening import perform_sanctions_search

    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = []
    mock_ctx = AsyncMock()
    mock_ctx.__aenter__.return_value = mock_conn
    mock_ctx.__aexit__.return_value = None

    with patch("database.postgres.get_async_db_read_conn", return_value=mock_ctx):
        res = await perform_sanctions_search("Wladimir Smirnow", 0.80, es=None)
        assert res["match_found"] is True
        assert res["source_list"] == "OFAC SDN List"
        assert res["matched_entry"]["name"] == "Wladimir Smirnow"

