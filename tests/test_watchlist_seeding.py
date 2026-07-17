import pytest
from unittest.mock import patch, AsyncMock
from services.watchlist_sync import WatchlistSyncEngine
from config import SANCTIONS_INDEX, PEP_INDEX


@pytest.mark.anyio
async def test_fetch_un_and_eu_sanctions_feeds():
    """Verify UN and EU sanctions feed parsers return normalized records with source list and entity types."""
    engine = WatchlistSyncEngine()

    un_records = await engine.fetch_un_sanctions_feed()
    assert len(un_records) > 0
    assert any("UN Consolidated Sanctions List" in r["source_list"] for r in un_records)

    eu_records = await engine.fetch_eu_sanctions_feed()
    assert len(eu_records) > 0
    assert any("EU Consolidated Sanctions List" in r["source_list"] for r in eu_records)


@pytest.mark.anyio
async def test_sync_all_watchlists_indexes_five_regulatory_sources():
    """Verify sync_all_watchlists indexes entries across OFAC, UN, EU, World-Check, and Dow Jones."""
    engine = WatchlistSyncEngine()
    mock_es = AsyncMock()

    with patch("services.watchlist_sync.get_async_elasticsearch_client", return_value=mock_es):
        result = await engine.sync_all_watchlists()

        assert result["status"] == "SYNCED"
        assert result["ofac_count"] > 0
        assert result["un_count"] > 0
        assert result["eu_count"] > 0
        assert result["worldcheck_count"] > 0
        assert result["dowjones_count"] > 0
        assert result["total_records_processed"] == (
            result["ofac_count"] + result["un_count"] + result["eu_count"] +
            result["worldcheck_count"] + result["dowjones_count"]
        )


@pytest.mark.anyio
async def test_ensure_indices_and_seed_triggers_initial_seeding():
    """Verify ensure_indices_and_seed creates missing indices and triggers sync when counts are 0."""
    engine = WatchlistSyncEngine()
    mock_es = AsyncMock()

    mock_es.indices.exists.return_value = False
    mock_es.count.return_value = {"count": 0}

    with patch.object(engine, "sync_all_watchlists", new_callable=AsyncMock) as mock_sync:
        mock_sync.return_value = {"status": "SYNCED"}

        res = await engine.ensure_indices_and_seed(es=mock_es)

        # Verify index creation calls for SANCTIONS_INDEX and PEP_INDEX
        assert mock_es.indices.create.call_count == 2
        mock_sync.assert_called_once()
        assert res["status"] == "SYNCED"
