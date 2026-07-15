import logging
import math
from database.neo4j_db import get_async_neo4j_driver

logger = logging.getLogger(__name__)

def tarjan_scc(graph: dict) -> list[list[str]]:
    """
    Implements Tarjan's Strongly Connected Components (SCC) algorithm
    to identify circular money flows (cycles) of size >= 2.
    Complexity: O(V + E)
    """
    index = 0
    stack = []
    indices = {}
    lowlinks = {}
    on_stack = set()
    sccs = []

    # Get all nodes in the graph
    all_nodes = set(graph.keys())
    for targets in graph.values():
        all_nodes.update(targets)

    def strongconnect(v):
        nonlocal index
        indices[v] = index
        lowlinks[v] = index
        index += 1
        stack.append(v)
        on_stack.add(v)

        for w in graph.get(v, []):
            if w not in indices:
                strongconnect(w)
                lowlinks[v] = min(lowlinks[v], lowlinks[w])
            elif w in on_stack:
                lowlinks[v] = min(lowlinks[v], indices[w])

        if lowlinks[v] == indices[v]:
            scc = []
            while True:
                w = stack.pop()
                on_stack.remove(w)
                scc.append(w)
                if w == v:
                    break
            # Only consider cycles of size >= 2
            if len(scc) >= 2:
                sccs.append(scc)

    for node in all_nodes:
        if node not in indices:
            strongconnect(node)
            
    return sccs

def compute_betweenness_centrality(graph: dict) -> dict:
    """
    Implements Brandes' algorithm to compute Betweenness Centrality
    for identifying intermediary/middleman accounts in the transaction flow.
    Complexity: O(V * E)
    """
    # Collect all nodes
    all_nodes = set(graph.keys())
    for targets in graph.values():
        all_nodes.update(targets)

    cb = {node: 0.0 for node in all_nodes}

    for s in all_nodes:
        # Stack S, path list P, sigma (path count) g, distance d, delta (dependency)
        S = []
        P = {w: [] for w in all_nodes}
        g = {w: 1.0 if w == s else 0.0 for w in all_nodes}
        d = {w: -1 for w in all_nodes}
        d[s] = 0
        Q = [s]

        # BFS shortest path search
        while Q:
            v = Q.pop(0)
            S.append(v)
            for w in graph.get(v, []):
                if d[w] < 0:
                    Q.append(w)
                    d[w] = d[v] + 1
                if d[w] == d[v] + 1:
                    g[w] += g[v]
                    P[w].append(v)

        delta = {w: 0.0 for w in all_nodes}
        while S:
            w = S.pop()
            for v in P[w]:
                delta[v] += (g[v] / g[w]) * (1.0 + delta[w])
            if w != s:
                cb[w] += delta[w]

    # Divide by 2 because the graph is directed but betweenness is accumulated on undirected paths
    # Or keep it as is since it is a directed representation of flows. Let's return raw scores rounded.
    return {node: round(score, 4) for node, score in cb.items()}

async def fetch_transaction_graph() -> dict:
    """
    Fetches the full transaction topology from Neo4j
    and builds an adjacency list.
    """
    driver = await get_async_neo4j_driver()
    query = """
        MATCH (s:Account)-[t:TRANSFERS_TO]->(r:Account)
        RETURN s.account_number AS sender, r.account_number AS receiver;
    """
    graph = {}
    try:
        async with driver.session() as session:
            result = await session.run(query)
            async for record in result:
                sender = record["sender"]
                receiver = record["receiver"]
                if sender not in graph:
                    graph[sender] = []
                if receiver not in graph:
                    graph[receiver] = []
                graph[sender].append(receiver)
    except Exception as e:
        logger.error(f"Failed to query Neo4j transaction graph: {e}")
        
    return graph

async def run_network_analysis() -> dict:
    """
    Analyzes the transaction graph to detect:
    - Circular money flows (Cycles via Tarjan's SCC)
    - Fan-In patterns (potential mules)
    - Fan-Out patterns (potential layering)
    - Key intermediaries (highest Betweenness Centrality)
    """
    graph = await fetch_transaction_graph()
    
    # 1. Detect Cycles (Circular Flows)
    cycles = tarjan_scc(graph)
    
    # Collect all unique nodes
    all_nodes = set(graph.keys())
    for targets in graph.values():
        all_nodes.update(targets)
        
    # Calculate degrees
    in_degrees = {node: 0 for node in all_nodes}
    out_degrees = {node: 0 for node in all_nodes}
    
    for u, neighbors in graph.items():
        out_degrees[u] = len(neighbors)
        for v in neighbors:
            in_degrees[v] += 1
            
    # 2. Detect Fan-In and Fan-Out Patterns
    # Fan-In: In-degree >= 3 and Out-degree <= 1
    # Fan-Out: Out-degree >= 3 and In-degree <= 1
    fan_in_nodes = []
    fan_out_nodes = []
    
    for node in all_nodes:
        ind = in_degrees[node]
        outd = out_degrees[node]
        if ind >= 3 and outd <= 1:
            fan_in_nodes.append({
                "account_number": node,
                "in_degree": ind,
                "out_degree": outd,
                "description": f"Fan-In pattern detected: account receives funds from {ind} unique sources but disperses to <= 1 targets."
            })
        if outd >= 3 and ind <= 1:
            fan_out_nodes.append({
                "account_number": node,
                "in_degree": ind,
                "out_degree": outd,
                "description": f"Fan-Out pattern detected: account distributes funds to {outd} unique targets with <= 1 sources."
            })
            
    # 3. Intermediaries via Betweenness Centrality
    centrality_scores = compute_betweenness_centrality(graph)
    sorted_intermediaries = sorted(centrality_scores.items(), key=lambda x: x[1], reverse=True)
    
    intermediaries = [
        {"account_number": node, "betweenness_centrality": score}
        for node, score in sorted_intermediaries if score > 0.0
    ]

    return {
        "circular_flows": [
            {
                "cycle": scc,
                "description": f"Circular flow cycle of size {len(scc)} detected: " + " -> ".join(scc) + f" -> {scc[0]}"
            }
            for scc in cycles
        ],
        "fan_in_alerts": fan_in_nodes,
        "fan_out_alerts": fan_out_nodes,
        "intermediary_ranking": intermediaries
    }
