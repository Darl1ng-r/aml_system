import pytest
from services.network_analysis import tarjan_scc, compute_betweenness_centrality


def test_tarjan_scc_finds_cycles():
    """Verify Tarjan SCC algorithm detects strongly connected components (cycles)."""
    adjacency = {
        "A": ["B"],
        "B": ["C"],
        "C": ["A", "D"],
        "D": []
    }

    sccs = tarjan_scc(adjacency)

    # SCC ["A", "B", "C"] forms a cycle of size 3
    cycle_sccs = [scc for scc in sccs if len(scc) > 1]
    assert len(cycle_sccs) == 1
    assert set(cycle_sccs[0]) == {"A", "B", "C"}


def test_betweenness_centrality_computes_intermediaries():
    """Verify Brandes algorithm computes exact betweenness centrality scores."""
    # Line graph A -> B -> C: B is the intermediary between A and C
    adjacency = {
        "A": ["B"],
        "B": ["C"],
        "C": []
    }

    centrality = compute_betweenness_centrality(adjacency)

    assert centrality["B"] > 0.0
    assert centrality["A"] == 0.0
    assert centrality["C"] == 0.0


@pytest.mark.anyio
async def test_detect_circular_flows_postgres():
    """Verify detect_circular_flows_postgres correctly parses recursive CTE paths and deduplicates cycles."""
    from unittest.mock import AsyncMock
    from services.network_analysis import detect_circular_flows_postgres

    mock_conn = AsyncMock()
    mock_conn.fetch.return_value = [
        {"path": ["ACC-001", "ACC-002", "ACC-003", "ACC-001"]},
        {"path": ["ACC-002", "ACC-003", "ACC-001", "ACC-002"]},  # Equivalent cycle, should be deduplicated
        {"path": ["ACC-010", "ACC-020", "ACC-010"]},             # 2-hop wash trade
    ]

    flows = await detect_circular_flows_postgres(
        conn=mock_conn,
        tenant_id="tenant-123",
        window_hours=48,
        max_depth=4,
        limit=50
    )

    # Verifies SQL was called with exact window_hours and tenant parameters
    mock_conn.fetch.assert_called_once()
    assert mock_conn.fetch.call_args[0][1] == "48"
    assert mock_conn.fetch.call_args[0][2] == "tenant-123"

    # Should deduplicate the 3-hop cycle down to 1 entry + 1 entry for the 2-hop cycle = 2 total
    assert len(flows) == 2
    assert flows[0]["cycle"] == ["ACC-001", "ACC-002", "ACC-003"]
    assert flows[1]["cycle"] == ["ACC-010", "ACC-020"]
    assert "PostgreSQL detected temporal circular flow" in flows[0]["description"]


@pytest.mark.anyio
async def test_run_network_analysis_binds_temporal_window():
    """Verify run_network_analysis passes min_epoch into Cypher queries when window_hours is specified."""
    from unittest.mock import AsyncMock, MagicMock, patch
    from services.network_analysis import run_network_analysis

    mock_session = AsyncMock()
    mock_session.run = AsyncMock()
    mock_session.run.return_value.__aiter__.return_value = []

    mock_driver = MagicMock()
    mock_driver.session.return_value.__aenter__.return_value = mock_session
    mock_driver.session.return_value.__aexit__.return_value = None

    with patch("services.network_analysis.get_async_neo4j_driver", AsyncMock(return_value=mock_driver)):
        res = await run_network_analysis(tenant_id="tenant-abc", window_hours=48)
        assert isinstance(res, dict)
        assert mock_session.run.called
        # Check that min_epoch was passed as an integer timestamp in Cypher kwargs
        call_kwargs = mock_session.run.call_args_list[0].kwargs
        assert "min_epoch" in call_kwargs
        assert isinstance(call_kwargs["min_epoch"], int)
        assert call_kwargs["tenant_id"] == "tenant-abc"


