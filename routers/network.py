from fastapi import APIRouter, Depends, HTTPException, Query
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter
from services.network_analysis import run_network_analysis

router = APIRouter(prefix="/api/v1/network", tags=["Network Analysis"])

@router.get("/analysis")
async def get_network_analysis(
    window_hours: int = 72,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Exposes graph network analytics for compliance dashboards.
    Returns:
    - Circular money flow cycles (Tarjan's SCC / Cypher directed cycles).
    - Fan-In patterns (potential mules).
    - Fan-Out patterns (potential layering).
    - Intermediary middleman transit accounts (Brandes' Betweenness Centrality).
    """
    try:
        tenant_id = enforce_tenant_data_scope(current_user)
        return await run_network_analysis(tenant_id=str(tenant_id) if tenant_id else None, window_hours=window_hours)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Graph network analysis failed: {str(e)}")

import logging

logger = logging.getLogger(__name__)


def _parse_neo4j_node(node) -> dict | None:
    if not node:
        return None
    n_id = node.get("id", str(node.element_id))
    label = node.get("account_number") or node.get("name") or n_id
    n_type = next(iter(node.labels)) if node.labels else "Account"
    return {"id": n_id, "label": label, "type": n_type, "properties": dict(node)}


def _parse_neo4j_records(records: list[dict]) -> dict:
    nodes = {}
    element_id_to_node_id = {}
    edges = []
    edge_ids = set()

    for rec in records:
        start_raw = rec.get("start")
        s_parsed = _parse_neo4j_node(start_raw)
        if s_parsed:
            nodes[s_parsed["id"]] = s_parsed
            element_id_to_node_id[str(start_raw.element_id)] = s_parsed["id"]

        conn_raw = rec.get("connected")
        c_parsed = _parse_neo4j_node(conn_raw)
        if c_parsed:
            nodes[c_parsed["id"]] = c_parsed
            element_id_to_node_id[str(conn_raw.element_id)] = c_parsed["id"]

        rels = rec.get("r")
        rel_list = rels if isinstance(rels, list) else [rels]
        for rel in rel_list:
            if not rel:
                continue
            src_id = element_id_to_node_id.get(str(rel.start_node_element_id), str(rel.start_node_element_id))
            dst_id = element_id_to_node_id.get(str(rel.end_node_element_id), str(rel.end_node_element_id))
            rel_id = f"{src_id}_{dst_id}"
            if rel_id not in edge_ids:
                edge_ids.add(rel_id)
                edges.append({
                    "id": rel_id,
                    "source": src_id,
                    "target": dst_id,
                    "type": rel.type,
                    "properties": dict(rel)
                })

    return {"nodes": list(nodes.values()), "edges": edges}


async def _expand_neo4j(entity_id: str, tenant_id: str | None, hops: int = 2) -> dict:
    from database.neo4j_db import get_async_neo4j_driver
    driver = await get_async_neo4j_driver()
    safe_hops = max(1, min(int(hops), 3))
    query = f"""
    MATCH (start {{id: $entity_id}})-[r:TRANSFERS_TO|BELONGS_TO|OWNS_UBO*1..{safe_hops}]-(connected)
    WHERE ($tenant_id IS NULL OR start.tenant_id = $tenant_id OR connected.tenant_id = $tenant_id)
    RETURN start, r, connected
    LIMIT 75;
    """
    async with driver.session() as session:
        result = await session.run(query, entity_id=entity_id, tenant_id=str(tenant_id) if tenant_id else None)
        records = await result.data()
    return _parse_neo4j_records(records)


def _derive_risk_label(score: float | None, status_val: str | None) -> str:
    if str(status_val or "").upper() == "FROZEN":
        return "CRITICAL"
    if score is None:
        return "STANDARD"
    if float(score) >= 0.85:
        return "CRITICAL"
    if float(score) >= 0.65:
        return "HIGH"
    return "STANDARD"


def _parse_pg_rows(rows: list) -> dict:
    pg_nodes = {}
    pg_edges = []
    seen_edges = set()
    for row in rows:
        s_id = str(row["sender_id"])
        r_id = str(row["receiver_id"])
        if s_id not in pg_nodes:
            s_risk = _derive_risk_label(row.get("sender_risk"), row.get("sender_status"))
            pg_nodes[s_id] = {
                "id": s_id,
                "label": row["sender_name"] or row["sender_acc"],
                "type": "Account",
                "properties": {
                    "account_number": row["sender_acc"],
                    "owner_name": row["sender_name"],
                    "risk": s_risk,
                    "risk_score": float(row.get("sender_risk") or 0.0)
                }
            }
        if r_id not in pg_nodes:
            r_risk = _derive_risk_label(row.get("receiver_risk"), row.get("receiver_status"))
            pg_nodes[r_id] = {
                "id": r_id,
                "label": row["receiver_name"] or row["receiver_acc"],
                "type": "Account",
                "properties": {
                    "account_number": row["receiver_acc"],
                    "owner_name": row["receiver_name"],
                    "risk": r_risk,
                    "risk_score": float(row.get("receiver_risk") or 0.0)
                }
            }
        tx_id = str(row["tx_id"])
        if tx_id not in seen_edges:
            seen_edges.add(tx_id)
            pg_edges.append({
                "id": tx_id,
                "source": s_id,
                "target": r_id,
                "type": "TRANSFERS_TO",
                "properties": {"amount": float(row["amount"]), "timestamp": str(row["timestamp"])}
            })
    return {"nodes": list(pg_nodes.values()), "edges": pg_edges}


async def _expand_pg_fallback(entity_id: str, tenant_id: str | None, hops: int = 2) -> dict:
    from database.postgres import get_async_db_read_conn
    safe_hops = max(1, min(int(hops), 3))
    async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
        rows = await conn.fetch(
            """
            WITH RECURSIVE visited_accounts(acc_id, depth) AS (
                SELECT id, 0
                FROM accounts
                WHERE id::text = $1 OR account_number = $1
                UNION
                SELECT CASE
                           WHEN t.sender_account_id = v.acc_id THEN t.receiver_account_id
                           ELSE t.sender_account_id
                       END,
                       v.depth + 1
                FROM visited_accounts v
                JOIN transactions t
                  ON t.sender_account_id = v.acc_id OR t.receiver_account_id = v.acc_id
                WHERE v.depth < $3
                  AND ($2::text IS NULL OR t.tenant_id = $2::uuid)
            )
            SELECT DISTINCT
                t.id as tx_id,
                t.amount,
                t.timestamp,
                s.id as sender_id,
                s.account_number as sender_acc,
                s.owner_name as sender_name,
                s.risk_score as sender_risk,
                s.status as sender_status,
                r.id as receiver_id,
                r.account_number as receiver_acc,
                r.owner_name as receiver_name,
                r.risk_score as receiver_risk,
                r.status as receiver_status
            FROM transactions t
            JOIN accounts s ON t.sender_account_id = s.id
            JOIN accounts r ON t.receiver_account_id = r.id
            WHERE (t.sender_account_id IN (SELECT acc_id FROM visited_accounts)
               AND t.receiver_account_id IN (SELECT acc_id FROM visited_accounts))
              AND ($2::text IS NULL OR t.tenant_id = $2::uuid)
            ORDER BY t.timestamp DESC
            LIMIT 75;
            """,
            str(entity_id), str(tenant_id) if tenant_id else None, safe_hops
        )
    return _parse_pg_rows(rows)


@router.get("/entities/{entity_id}/network")
@router.get("/nodes/{entity_id}/neighbors")
@router.get("/expand/{entity_id}")
async def expand_graph_node(
    entity_id: str,
    hops: int = Query(default=2, ge=1, le=3, description="Traversal depth in hops (1-3)"),
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Dynamically expands a target graph node by fetching its N-hop connected sub-network from Neo4j,
    scoped strictly to the authenticated tenant (B4).
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    try:
        return await _expand_neo4j(entity_id, tenant_id, hops=hops)
    except Exception as neo_err:
        logger.info(f"Neo4j expansion unavailable ({neo_err}); executing in-engine PostgreSQL fallback...")
        try:
            return await _expand_pg_fallback(entity_id, tenant_id, hops=hops)
        except Exception as pg_err:
            raise HTTPException(
                status_code=500,
                detail=f"Graph node expansion failed on both Neo4j ({neo_err}) and PostgreSQL ({pg_err})"
            )
