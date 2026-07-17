import pytest
import hashlib
from unittest.mock import patch, AsyncMock
from services.watchlist_sync import WatchlistSyncEngine


@pytest.mark.anyio
async def test_watchlist_sync_idempotency_and_deterministic_ids():
    """Verify sync_all_watchlists uses deterministic IDs and op_type='index' across multiple sync runs."""
    engine = WatchlistSyncEngine()

    mock_es = AsyncMock()

    with patch("services.watchlist_sync.get_async_elasticsearch_client", return_value=mock_es):
        # Run sync cycle 1
        result1 = await engine.sync_all_watchlists()
        assert result1["status"] == "SYNCED"

        calls_run1 = mock_es.index.call_args_list
        indexed_ids_run1 = [call.kwargs["id"] for call in calls_run1]

        # Verify all calls used op_type='index'
        for call in calls_run1:
            assert call.kwargs["op_type"] == "index"

        # Reset mock call history
        mock_es.index.reset_mock()

        # Run sync cycle 2 (simulating repeated sync)
        result2 = await engine.sync_all_watchlists()
        assert result2["status"] == "SYNCED"

        calls_run2 = mock_es.index.call_args_list
        indexed_ids_run2 = [call.kwargs["id"] for call in calls_run2]

        # Verify exact same deterministic IDs are generated across runs (100% idempotent)
        assert indexed_ids_run1 == indexed_ids_run2
        assert len(indexed_ids_run1) == result1["total_records_processed"]


@pytest.mark.anyio
async def test_watchlist_sync_idempotency_order_independence():
    """Verify that document IDs are derived strictly from entity attributes and remain identical even when list position changes."""
    engine = WatchlistSyncEngine()

    mock_es = AsyncMock()

    ofac_run1 = [
        {"name": "Alpha Corp", "source_list": "OFAC SDN List", "entity_type": "Entity", "program": "SANCTION_A"},
        {"name": "Jane Doe", "source_list": "OFAC SDN List", "entity_type": "Individual", "program": "SANCTION_B"},
    ]
    # In run 2, new item inserted at index 0 (shifting all positions)
    ofac_run2 = [
        {"name": "New Entry X", "source_list": "OFAC SDN List", "entity_type": "Entity", "program": "SANCTION_C"},
        {"name": "Jane Doe", "source_list": "OFAC SDN List", "entity_type": "Individual", "program": "SANCTION_B"},
        {"name": "Alpha Corp", "source_list": "OFAC SDN List", "entity_type": "Entity", "program": "SANCTION_A"},
    ]

    with patch("services.watchlist_sync.get_async_elasticsearch_client", return_value=mock_es):
        with patch.object(engine, "fetch_ofac_sdn_feed", side_effect=[ofac_run1, ofac_run2]):
            await engine.sync_all_watchlists()
            ids_run1 = {call.kwargs["document"]["name"]: call.kwargs["id"] for call in mock_es.index.call_args_list}

            mock_es.index.reset_mock()

            await engine.sync_all_watchlists()
            ids_run2 = {call.kwargs["document"]["name"]: call.kwargs["id"] for call in mock_es.index.call_args_list}

            # "Alpha Corp" and "Jane Doe" must have identical document IDs despite positional index shift
            assert ids_run1["Alpha Corp"] == ids_run2["Alpha Corp"]
            assert ids_run1["Jane Doe"] == ids_run2["Jane Doe"]

