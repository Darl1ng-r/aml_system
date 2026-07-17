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
