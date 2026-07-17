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
