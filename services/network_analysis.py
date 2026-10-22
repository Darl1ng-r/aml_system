import logging
import math
from datetime import datetime, timezone
from database.neo4j_db import get_async_neo4j_driver

logger = logging.getLogger(__name__)

class _TarjanSCC:
    def __init__(self, graph: dict):
        self.graph = graph
        self.index = 0
        self.stack: list[str] = []
        self.indices: dict[str, int] = {}
        self.lowlinks: dict[str, int] = {}
        self.on_stack: set[str] = set()
        self.sccs: list[list[str]] = []

    def _collect_all_nodes(self) -> set[str]:
        nodes = set(self.graph.keys())
        for targets in self.graph.values():
            nodes.update(targets)
        return nodes

    def _pop_component(self, root: str) -> list[str]:
        scc = []
        while self.stack:
            w = self.stack.pop()
            self.on_stack.discard(w)
            scc.append(w)
            if w == root:
                break
        return scc

    def _process_neighbor(self, v: str, w: str) -> None:
        if w not in self.indices:
            self._strongconnect(w)
            self.lowlinks[v] = min(self.lowlinks[v], self.lowlinks[w])
        elif w in self.on_stack:
            self.lowlinks[v] = min(self.lowlinks[v], self.indices[w])

    def _strongconnect(self, v: str) -> None:
        self.indices[v] = self.index
        self.lowlinks[v] = self.index
        self.index += 1
        self.stack.append(v)
        self.on_stack.add(v)

        for w in self.graph.get(v, []):
            self._process_neighbor(v, w)

        if self.lowlinks[v] == self.indices[v]:
            scc = self._pop_component(v)
            if len(scc) >= 2:
                self.sccs.append(scc)

    def run(self) -> list[list[str]]:
        for node in self._collect_all_nodes():
            if node not in self.indices:
                self._strongconnect(node)
        return self.sccs

def tarjan_scc(graph: dict) -> list[list[str]]:
    """
    Implements Tarjan's Strongly Connected Components (SCC) algorithm
    to identify circular money flows (cycles) of size >= 2.
    Complexity: O(V + E)
    """
    return _TarjanSCC(graph).run()

def _collect_graph_nodes(graph: dict) -> set:
    nodes = set(graph.keys())
    for targets in graph.values():
        nodes.update(targets)
    return nodes

def _brandes_bfs(graph: dict, s: str, all_nodes: set):
    S = []
    P = {w: [] for w in all_nodes}
    g = {w: 1.0 if w == s else 0.0 for w in all_nodes}
    d = {w: -1 for w in all_nodes}
    d[s] = 0
    Q = [s]

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
    return S, P, g

def _brandes_accumulate(s: str, stack_s: list, path_p: dict, g: dict, cb: dict, all_nodes: set) -> None:
    delta = dict.fromkeys(all_nodes, 0.0)
    while stack_s:
        w = stack_s.pop()
        for v in path_p[w]:
            delta[v] += (g[v] / g[w]) * (1.0 + delta[w])
        if w != s:
            cb[w] += delta[w]

def compute_betweenness_centrality(graph: dict) -> dict:
    """
    Implements Brandes' algorithm to compute Betweenness Centrality
    for identifying intermediary/middleman accounts in the transaction flow.
    Complexity: O(V * E)
    """
    all_nodes = _collect_graph_nodes(graph)
    cb = dict.fromkeys(all_nodes, 0.0)

    for s in all_nodes:
        stack_s, path_p, g = _brandes_bfs(graph, s, all_nodes)
        _brandes_accumulate(s, stack_s, path_p, g, cb, all_nodes)

    n = len(all_nodes)
    scale = (n - 1) * (n - 2) if n > 2 else 1.0
    return {node: round(score / scale, 4) for node, score in cb.items()}

async def detect_circular_flows_postgres(
    conn=None,
    tenant_id: str | None = None,
    window_hours: int = 48,
    max_depth: int = 4,
    limit: int = 50
) -> list[dict]:
    """
    Detects forward-moving circular money flows (layering cycles) directly in PostgreSQL
    using a recursive CTE with temporal causality constraints (A -> B -> C -> A within window_hours).
    Provides institutional zero-infrastructure fallback without requiring external graph databases.
    """
    query = """
    WITH RECURSIVE tx_window AS (
        SELECT 
            s.account_number AS sender,
            r.account_number AS receiver,
            t.amount,
            t.timestamp
        FROM transactions t
        JOIN accounts s ON t.sender_account_id = s.id
        JOIN accounts r ON t.receiver_account_id = r.id
        WHERE t.timestamp >= NOW() - ($1 || ' hours')::interval
          AND ($2::text IS NULL OR t.tenant_id = $2::uuid)
          AND t.status IN ('COMPLETED', 'PENDING')
    ),
    paths AS (
        -- Anchor: 1-hop path
        SELECT 
            sender AS root,
            receiver AS current_node,
            ARRAY[sender, receiver]::text[] AS path,
            1 AS depth,
            timestamp AS start_time,
            timestamp AS last_time
        FROM tx_window
        
        UNION ALL
        
        -- Recursive step: next hop must occur after previous hop
        SELECT 
            p.root,
            w.receiver AS current_node,
            p.path || w.receiver,
            p.depth + 1,
            p.start_time,
            w.timestamp AS last_time
        FROM paths p
        JOIN tx_window w ON p.current_node = w.sender
        WHERE p.depth < $3
          AND w.timestamp >= p.last_time
          AND (w.receiver = p.root OR NOT (w.receiver = ANY(p.path)))
    )
    SELECT DISTINCT path
    FROM paths
    WHERE current_node = root AND depth >= 2
    LIMIT $4;
    """

    async def _query_exec(db_conn):
        rows = await db_conn.fetch(query, str(window_hours), tenant_id, max_depth, limit)
        circular_flows = []
        seen = set()
        for row in rows:
            path = list(row["path"])
            cycle_nodes = path[:-1] if path and path[0] == path[-1] else path
            cycle_key = tuple(sorted(cycle_nodes))
            if len(cycle_nodes) >= 2 and cycle_key not in seen:
                seen.add(cycle_key)
                circular_flows.append({
                    "cycle": cycle_nodes,
                    "description": f"PostgreSQL detected temporal circular flow of size {len(cycle_nodes)}: " + " -> ".join(cycle_nodes) + f" -> {cycle_nodes[0]}"
                })
        return circular_flows

    if conn is not None:
        return await _query_exec(conn)
    else:
        try:
            from database.postgres import get_async_db_conn
            async with get_async_db_conn(tenant_id=tenant_id) as db_conn:
                return await _query_exec(db_conn)
        except Exception as e:
            logger.warning(f"PostgreSQL circular flow detection failed: {e}")
            return []

def _calc_min_epoch(window_hours: int | None) -> int | None:
    if window_hours is None:
        return None
    return int(datetime.now(timezone.utc).timestamp()) - (window_hours * 3600)

def _add_edge_to_graph(graph: dict, sender: str, receiver: str) -> None:
    if sender not in graph:
        graph[sender] = []
    if receiver not in graph:
        graph[receiver] = []
    graph[sender].append(receiver)

async def _fetch_graph_neo4j(tenant_id: str | None, min_epoch: int | None, limit: int) -> tuple[dict, bool]:
    query = """
        MATCH (s:Account)-[t:TRANSFERS_TO]->(r:Account)
        WHERE ($tenant_id IS NULL OR t.tenant_id = $tenant_id OR s.tenant_id = $tenant_id)
          AND ($min_epoch IS NULL OR t.timestamp IS NULL OR t.timestamp >= $min_epoch)
        RETURN s.account_number AS sender, r.account_number AS receiver
        LIMIT $limit;
    """
    graph: dict = {}
    try:
        driver = await get_async_neo4j_driver()
        if not driver:
            return graph, False
        async with driver.session() as session:
            result = await session.run(query, tenant_id=tenant_id, min_epoch=min_epoch, limit=limit)
            async for record in result:
                _add_edge_to_graph(graph, record["sender"], record["receiver"])
        return graph, True
    except Exception as e:
        logger.info(f"Neo4j transaction graph unavailable ({e}); executing native PostgreSQL fallback...")
        return graph, False

async def _fetch_graph_postgres(tenant_id: str | None, window_hours: int | None, limit: int) -> dict:
    graph: dict = {}
    try:
        from database.postgres import get_async_db_read_conn
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            rows = await conn.fetch(
                """
                SELECT s.account_number AS sender, r.account_number AS receiver
                FROM transactions t
                JOIN accounts s ON t.sender_account_id = s.id
                JOIN accounts r ON t.receiver_account_id = r.id
                WHERE ($1::text IS NULL OR t.tenant_id = $1::uuid)
                  AND ($2::int IS NULL OR t.timestamp >= NOW() - ($2 || ' hours')::interval)
                  AND t.status IN ('COMPLETED', 'PENDING')
                LIMIT $3;
                """,
                str(tenant_id) if tenant_id else None,
                window_hours,
                limit
            )
            for row in rows:
                _add_edge_to_graph(graph, row["sender"], row["receiver"])
    except Exception as pg_err:
        logger.warning(f"PostgreSQL graph topology query fallback warning: {pg_err}")
    return graph

async def fetch_transaction_graph(
    tenant_id: str | None = None,
    limit: int = 2000,
    window_hours: int | None = 72
) -> dict:
    """
    Fetches transaction topology from Neo4j up to a safe limit,
    scoped by tenant_id to prevent cross-tenant data leakage (B4)
    and bounded by a temporal window (window_hours) to focus on active money movement.
    """
    min_epoch = _calc_min_epoch(window_hours)
    graph, neo4j_success = await _fetch_graph_neo4j(tenant_id, min_epoch, limit)
    if not neo4j_success or not graph:
        graph = await _fetch_graph_postgres(tenant_id, window_hours, limit)
    return graph

async def _detect_cypher_degrees(driver, tenant_id: str | None, min_epoch: int | None) -> tuple[list[dict], list[dict], bool]:
    fan_in_nodes: list[dict] = []
    fan_out_nodes: list[dict] = []
    if not driver:
        return fan_in_nodes, fan_out_nodes, False
    try:
        degree_query = """
        MATCH (a:Account)
        WHERE ($tenant_id IS NULL OR a.tenant_id = $tenant_id)
        OPTIONAL MATCH (s:Account)-[t1:TRANSFERS_TO]->(a)
        WHERE ($tenant_id IS NULL OR t1.tenant_id = $tenant_id)
          AND ($min_epoch IS NULL OR t1.timestamp IS NULL OR t1.timestamp >= $min_epoch)
        WITH a, count(DISTINCT s) AS in_degree
        OPTIONAL MATCH (a)-[t2:TRANSFERS_TO]->(r:Account)
        WHERE ($tenant_id IS NULL OR t2.tenant_id = $tenant_id)
          AND ($min_epoch IS NULL OR t2.timestamp IS NULL OR t2.timestamp >= $min_epoch)
        WITH a, in_degree, count(DISTINCT r) AS out_degree
        WHERE (in_degree >= 3 AND out_degree <= 1) OR (out_degree >= 3 AND in_degree <= 1)
        RETURN a.account_number AS account_number, in_degree, out_degree
        LIMIT 100;
        """
        async with driver.session() as session:
            res = await session.run(degree_query, tenant_id=tenant_id, min_epoch=min_epoch)
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
        return fan_in_nodes, fan_out_nodes, True
    except Exception as e:
        logger.warning(f"Server-side Cypher degree calculation failed ({e}), falling back to bounded in-memory.")
        return fan_in_nodes, fan_out_nodes, False

async def _detect_cypher_cycles(driver, tenant_id: str | None, min_epoch: int | None) -> tuple[list[dict], bool]:
    circular_flows: list[dict] = []
    if not driver:
        return circular_flows, False
    try:
        cycle_query = """
        MATCH path = (a:Account)-[t:TRANSFERS_TO*2..5]->(a)
        WHERE ($tenant_id IS NULL OR ALL(rel IN relationships(path) WHERE rel.tenant_id = $tenant_id))
          AND ($min_epoch IS NULL OR ALL(rel IN relationships(path) WHERE rel.timestamp IS NULL OR rel.timestamp >= $min_epoch))
        WITH [n IN nodes(path) | n.account_number] AS node_list
        RETURN DISTINCT node_list AS cycle
        LIMIT 50;
        """
        async with driver.session() as session:
            res = await session.run(cycle_query, tenant_id=tenant_id, min_epoch=min_epoch)
            seen_cycles = set()
            async for record in res:
                cycle = record["cycle"]
                unique_nodes = list(dict.fromkeys(cycle[:-1]))
                cycle_key = tuple(sorted(unique_nodes))
                if len(unique_nodes) >= 2 and cycle_key not in seen_cycles:
                    seen_cycles.add(cycle_key)
                    circular_flows.append({
                        "cycle": unique_nodes,
                        "description": f"Circular flow cycle of size {len(unique_nodes)} detected: " + " -> ".join(unique_nodes) + f" -> {unique_nodes[0]}"
                    })
        return circular_flows, True
    except Exception as e:
        logger.warning(f"Server-side Cypher cycle search failed ({e}), falling back to Tarjan SCC.")
        return circular_flows, False

async def _detect_gds_betweenness(driver) -> tuple[list[dict], bool]:
    intermediaries: list[dict] = []
    if not driver:
        return intermediaries, False
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
        return intermediaries, True
    except Exception as e:
        logger.info(f"Neo4j GDS not active or projection missing ({e}), using bounded algorithmic fallback.")
        return intermediaries, False

def _find_simple_cycle_in_scc(graph: dict, scc: list[str]) -> list[str] | None:
    scc_set = set(scc)
    start = scc[0]
    queue = [(start, [start])]
    while queue:
        curr, path = queue.pop(0)
        for nxt in graph.get(curr, []):
            if nxt not in scc_set:
                continue
            if nxt == start and len(path) >= 2:
                return path
            if nxt not in path and len(path) < min(len(scc) + 1, 6):
                queue.append((nxt, path + [nxt]))
    return None

def _compute_tarjan_cycle_fallback(graph: dict) -> list[dict]:
    cycles = tarjan_scc(graph)
    circular_flows = []
    for scc in cycles:
        detected_cycle = _find_simple_cycle_in_scc(graph, scc)
        cycle_nodes = detected_cycle if detected_cycle else scc
        if detected_cycle:
            desc = f"Circular flow cycle of size {len(detected_cycle)} detected: " + " -> ".join(detected_cycle) + f" -> {detected_cycle[0]}"
        else:
            desc = f"Strongly connected circular flow cluster of {len(scc)} accounts: {', '.join(scc)}"
        circular_flows.append({
            "cycle": cycle_nodes,
            "description": desc
        })
    return circular_flows

def _compute_degree_fallback(graph: dict) -> tuple[list[dict], list[dict]]:
    all_nodes = _collect_graph_nodes(graph)
    in_degrees = dict.fromkeys(all_nodes, 0)
    out_degrees = dict.fromkeys(all_nodes, 0)
    for u, neighbors in graph.items():
        out_degrees[u] = len(neighbors)
        for v in neighbors:
            in_degrees[v] += 1

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
    return fan_in_nodes, fan_out_nodes

def _compute_centrality_fallback(graph: dict) -> list[dict]:
    if not graph:
        return []
    centrality_scores = compute_betweenness_centrality(graph)
    sorted_intermediaries = sorted(centrality_scores.items(), key=lambda x: x[1], reverse=True)
    return [
        {"account_number": node, "betweenness_centrality": score}
        for node, score in sorted_intermediaries if score > 0.0
    ]

async def run_network_analysis(
    tenant_id: str | None = None,
    window_hours: int | None = 72
) -> dict:
    """
    Analyzes the transaction graph scoped to tenant_id (B4) and bounded by window_hours (default 72h) to detect:
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

    min_epoch = _calc_min_epoch(window_hours)
    fan_in_nodes, fan_out_nodes, cypher_degrees_success = await _detect_cypher_degrees(driver, tenant_id, min_epoch)
    circular_flows, cypher_cycles_success = await _detect_cypher_cycles(driver, tenant_id, min_epoch)
    intermediaries, gds_success = await _detect_gds_betweenness(driver)

    if not cypher_degrees_success or not cypher_cycles_success or not gds_success:
        graph = await fetch_transaction_graph(tenant_id=tenant_id, limit=2000, window_hours=window_hours)
        if not cypher_cycles_success:
            circular_flows = _compute_tarjan_cycle_fallback(graph)
        if not cypher_degrees_success:
            fan_in_nodes, fan_out_nodes = _compute_degree_fallback(graph)
        if not gds_success:
            intermediaries = _compute_centrality_fallback(graph)

    return {
        "circular_flows": circular_flows,
        "fan_in_alerts": fan_in_nodes,
        "fan_out_alerts": fan_out_nodes,
        "intermediary_ranking": intermediaries
    }


async def compute_transitive_counterparty_taint(
    account_number: str,
    tenant_id: str | None = None,
    max_hops: int = 2,
    decay_factor: float = 0.65
) -> float:
    """
    Computes upstream illicit taint propagation using graph traversal.
    If an account received funds from an upstream high-risk entity (risk_score >= 0.75)
    up to max_hops away, transitive risk propagates decaying with hop distance.
    Returns taint score in [0.0, 1.0].
    """
    try:
        driver = await get_async_neo4j_driver()
        cypher_query = """
        MATCH path = (origin:Account)-[t:TRANSFERS_TO*1..2]->(target:Account {account_number: $acc_num})
        WHERE ($tenant_id IS NULL OR origin.tenant_id = $tenant_id)
          AND coalesce(origin.risk_score, 0.0) >= 0.75
        WITH path, origin.risk_score AS upstream_risk, length(path) AS hops
        RETURN max(upstream_risk * ($decay ^ hops)) AS taint_score;
        """
        async with driver.session() as session:
            result = await session.run(
                cypher_query,
                acc_num=account_number,
                tenant_id=tenant_id,
                decay=decay_factor
            )
            record = await result.single()
            if record and record["taint_score"] is not None:
                return round(float(record["taint_score"]), 4)
    except Exception as e:
        logger.debug(f"Neo4j transitive taint bypassed ({e}); querying PostgreSQL 16 recursive CTE directly...")
        try:
            from database.postgres import get_async_db_read_conn
            async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
                row = await conn.fetchrow(
                    """
                    WITH RECURSIVE upstream AS (
                        SELECT 
                            s.id AS origin_id, 
                            s.risk_score, 
                            1 AS hops
                        FROM transactions t
                        JOIN accounts target ON t.receiver_account_id = target.id
                        JOIN accounts s ON t.sender_account_id = s.id
                        WHERE target.account_number = $1
                          AND ($2::text IS NULL OR t.tenant_id = $2::uuid)
                          AND t.status IN ('COMPLETED', 'PENDING')
                          
                        UNION ALL
                        
                        SELECT 
                            s.id AS origin_id, 
                            s.risk_score, 
                            u.hops + 1 AS hops
                        FROM upstream u
                        JOIN transactions t ON t.receiver_account_id = u.origin_id
                        JOIN accounts s ON t.sender_account_id = s.id
                        WHERE u.hops < $4
                          AND ($2::text IS NULL OR t.tenant_id = $2::uuid)
                          AND t.status IN ('COMPLETED', 'PENDING')
                    )
                    SELECT COALESCE(MAX(risk_score * power($3::float, hops)), 0.0) as taint_score
                    FROM upstream
                    WHERE risk_score >= 0.75;
                    """,
                    account_number,
                    str(tenant_id) if tenant_id else None,
                    decay_factor,
                    max_hops
                )
                if row and row["taint_score"] is not None:
                    return round(float(row["taint_score"]), 4)
        except Exception as pg_err:
            logger.warning(f"PostgreSQL transitive taint fallback warning: {pg_err}")

    return 0.0


