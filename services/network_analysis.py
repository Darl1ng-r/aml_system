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

async def fetch_transaction_graph(limit: int = 2000) -> dict:
    """
    Fetches transaction topology from Neo4j up to a safe limit
    to build an adjacency list without memory exhaustion.
    """
    driver = await get_async_neo4j_driver()
    query = """
        MATCH (s:Account)-[t:TRANSFERS_TO]->(r:Account)
        RETURN s.account_number AS sender, r.account_number AS receiver
        LIMIT $limit;
    """
    graph = {}
    try:
        async with driver.session() as session:
            result = await session.run(query, limit=limit)
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
    - Circular money flows (Server-side Cypher / GDS SCC / Tarjan's SCC fallback)
    - Fan-In patterns (potential mules via server-side aggregation)
    - Fan-Out patterns (potential layering via server-side aggregation)
    - Key intermediaries (Neo4j GDS Betweenness Centrality / Brandes fallback)
    """
    driver = None
    try:
        driver = await get_async_neo4j_driver()
    except Exception as e:
        logger.warning(f"Neo4j driver unavailable for server-side graph analysis: {e}")

    # 1. Server-side Fan-In and Fan-Out Detection via Cypher
    fan_in_nodes = []
    fan_out_nodes = []
    cypher_degrees_success = False

    if driver:
        try:
            degree_query = """
            MATCH (a:Account)
            OPTIONAL MATCH (s:Account)-[:TRANSFERS_TO]->(a)
            WITH a, count(DISTINCT s) AS in_degree
            OPTIONAL MATCH (a)-[:TRANSFERS_TO]->(r:Account)
            WITH a, in_degree, count(DISTINCT r) AS out_degree
            WHERE (in_degree >= 3 AND out_degree <= 1) OR (out_degree >= 3 AND in_degree <= 1)
            RETURN a.account_number AS account_number, in_degree, out_degree
            LIMIT 100;
            """
            async with driver.session() as session:
                res = await session.run(degree_query)
                async for record in res:
                    acc = record["account_number"]
                    ind = record["in_degree"]
                    outd = record["out_degree"]
                    if ind >= 3 and outd <= 1:
                        fan_in_nodes.append({
                            "account_number": acc,
                            "in_degree": ind,
                            "out_degree": outd,
                            "description": f"Fan-In pattern detected: account receives funds from {ind} unique sources but disperses to <= 1 targets."
                        })
                    if outd >= 3 and ind <= 1:
                        fan_out_nodes.append({
                            "account_number": acc,
                            "in_degree": ind,
                            "out_degree": outd,
                            "description": f"Fan-Out pattern detected: account distributes funds to {outd} unique targets with <= 1 sources."
                        })
            cypher_degrees_success = True
        except Exception as e:
            logger.warning(f"Server-side Cypher degree calculation failed ({e}), falling back to bounded in-memory.")

    # 2. Circular Flow Detection (Server-side Cypher cycle finding or Tarjan fallback)
    circular_flows = []
    cypher_cycles_success = False

    if driver:
        try:
            cycle_query = """
            MATCH path = (a:Account)-[:TRANSFERS_TO*2..5]->(a)
            WITH [n IN nodes(path) | n.account_number] AS node_list
            RETURN DISTINCT node_list AS cycle
            LIMIT 50;
            """
            async with driver.session() as session:
                res = await session.run(cycle_query)
                seen_cycles = set()
                async for record in res:
                    cycle = record["cycle"]
                    # Normalize cycle representation
                    unique_nodes = list(dict.fromkeys(cycle[:-1]))
                    cycle_key = tuple(sorted(unique_nodes))
                    if len(unique_nodes) >= 2 and cycle_key not in seen_cycles:
                        seen_cycles.add(cycle_key)
                        circular_flows.append({
                            "cycle": unique_nodes,
                            "description": f"Circular flow cycle of size {len(unique_nodes)} detected: " + " -> ".join(unique_nodes) + f" -> {unique_nodes[0]}"
                        })
            cypher_cycles_success = True
        except Exception as e:
            logger.warning(f"Server-side Cypher cycle search failed ({e}), falling back to Tarjan SCC.")

    # 3. Intermediary Detection (Neo4j GDS Betweenness Centrality or Brandes fallback)
    intermediaries = []
    gds_success = False

    if driver:
        try:
            gds_query = """
            CALL gds.betweenness.stream('amlGraph')
            YIELD nodeId, score
            WHERE score > 0.0
            RETURN gds.util.asNode(nodeId).account_number AS account_number, round(score, 4) AS betweenness_centrality
            ORDER BY betweenness_centrality DESC
            LIMIT 50;
            """
            async with driver.session() as session:
                res = await session.run(gds_query)
                async for record in res:
                    intermediaries.append({
                        "account_number": record["account_number"],
                        "betweenness_centrality": float(record["betweenness_centrality"])
                    })
            gds_success = True
        except Exception as e:
            logger.info(f"Neo4j GDS not active or projection missing ({e}), using bounded algorithmic fallback.")

    # If any analytics component failed server-side execution, run bounded in-memory fallback
    if not cypher_degrees_success or not cypher_cycles_success or not gds_success:
        graph = await fetch_transaction_graph(limit=2000)
        
        # Fallback for cycles
        if not cypher_cycles_success:
            cycles = tarjan_scc(graph)
            circular_flows = [
                {
                    "cycle": scc,
                    "description": f"Circular flow cycle of size {len(scc)} detected: " + " -> ".join(scc) + f" -> {scc[0]}"
                }
                for scc in cycles
            ]

        # Fallback for Fan-In / Fan-Out
        if not cypher_degrees_success:
            all_nodes = set(graph.keys())
            for targets in graph.values():
                all_nodes.update(targets)
            in_degrees = {node: 0 for node in all_nodes}
            out_degrees = {node: 0 for node in all_nodes}
            for u, neighbors in graph.items():
                out_degrees[u] = len(neighbors)
                for v in neighbors:
                    in_degrees[v] += 1
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

        # Fallback for Betweenness Centrality
        if not gds_success and graph:
            centrality_scores = compute_betweenness_centrality(graph)
            sorted_intermediaries = sorted(centrality_scores.items(), key=lambda x: x[1], reverse=True)
            intermediaries = [
                {"account_number": node, "betweenness_centrality": score}
                for node, score in sorted_intermediaries if score > 0.0
            ]

    return {
        "circular_flows": circular_flows,
        "fan_in_alerts": fan_in_nodes,
        "fan_out_alerts": fan_out_nodes,
        "intermediary_ranking": intermediaries
    }
