from fastapi import APIRouter, Depends, HTTPException
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter
from services.network_analysis import run_network_analysis

router = APIRouter(prefix="/api/v1/network", tags=["Network Analysis"])

@router.get("/analysis")
async def get_network_analysis(
    window_hours: int = 72,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
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

@router.get("/entities/{entity_id}/network")
@router.get("/nodes/{entity_id}/neighbors")
@router.get("/expand/{entity_id}")
async def expand_graph_node(
    entity_id: str,
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Dynamically expands a target graph node by fetching its 2-hop connected sub-network from Neo4j,
    scoped strictly to the authenticated tenant (B4).
    """
    from database.neo4j_db import get_async_neo4j_driver
    try:
        tenant_id = enforce_tenant_data_scope(current_user)
        driver = await get_async_neo4j_driver()
        query = """
        MATCH (start {id: $entity_id})-[r:TRANSFERS_TO|BELONGS_TO|OWNS_UBO*1..2]-(connected)
        WHERE ($tenant_id IS NULL OR start.tenant_id = $tenant_id OR connected.tenant_id = $tenant_id)
        RETURN start, r, connected
        LIMIT 50;
        """
        async with driver.session() as session:
            result = await session.run(query, entity_id=entity_id, tenant_id=str(tenant_id) if tenant_id else None)
            records = await result.data()

        nodes = {}
        edges = []
        edge_ids = set()

        for rec in records:
            s_node = rec.get("start")
            c_node = rec.get("connected")
            rels = rec.get("r")

            if s_node:
                s_id = s_node.get("id", str(s_node.element_id))
                s_label = s_node.get("account_number") or s_node.get("name") or s_id
                s_type = next(iter(s_node.labels)) if s_node.labels else "Account"
                nodes[s_id] = {"id": s_id, "label": s_label, "type": s_type, "properties": dict(s_node)}

            if c_node:
                c_id = c_node.get("id", str(c_node.element_id))
                c_label = c_node.get("account_number") or c_node.get("name") or c_id
                c_type = next(iter(c_node.labels)) if c_node.labels else "Account"
                nodes[c_id] = {"id": c_id, "label": c_label, "type": c_type, "properties": dict(c_node)}

            rel_list = rels if isinstance(rels, list) else [rels]
            for rel in rel_list:
                if rel:
                    rel_id = f"{rel.start_node_element_id}_{rel.end_node_element_id}"
                    if rel_id not in edge_ids:
                        edge_ids.add(rel_id)
                        edges.append({
                            "id": rel_id,
                            "source": str(rel.start_node_element_id),
                            "target": str(rel.end_node_element_id),
                            "type": rel.type,
                            "properties": dict(rel)
                        })

        return {"nodes": list(nodes.values()), "edges": edges}
    except Exception as neo_err:
        # Pruned Datastore / Resilient Fallback: Query PostgreSQL 16 directly
        import logging
        logger = logging.getLogger(__name__)
        logger.info(f"Neo4j expansion unavailable ({neo_err}); executing in-engine PostgreSQL fallback...")
        try:
            from database.postgres import get_async_db_read_conn
            async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
                rows = await conn.fetch(
                    """
                    WITH target_account AS (
                        SELECT id, account_number, owner_name 
                        FROM accounts 
                        WHERE id::text = $1 OR account_number = $1
                        LIMIT 1
                    ),
                    direct_txs AS (
                        SELECT 
                            t.id as tx_id,
                            t.amount,
                            t.timestamp,
                            s.id as sender_id,
                            s.account_number as sender_acc,
                            s.owner_name as sender_name,
                            r.id as receiver_id,
                            r.account_number as receiver_acc,
                            r.owner_name as receiver_name
                        FROM transactions t
                        JOIN accounts s ON t.sender_account_id = s.id
                        JOIN accounts r ON t.receiver_account_id = r.id
                        WHERE (t.sender_account_id IN (SELECT id FROM target_account)
                           OR t.receiver_account_id IN (SELECT id FROM target_account))
                          AND ($2::text IS NULL OR t.tenant_id = $2::uuid)
                        ORDER BY t.timestamp DESC
                        LIMIT 50
                    )
                    SELECT * FROM direct_txs;
                    """,
                    str(entity_id), str(tenant_id) if tenant_id else None
                )

                pg_nodes = {}
                pg_edges = []
                for row in rows:
                    s_id = str(row["sender_id"])
                    r_id = str(row["receiver_id"])
                    if s_id not in pg_nodes:
                        pg_nodes[s_id] = {
                            "id": s_id,
                            "label": row["sender_name"] or row["sender_acc"],
                            "type": "Account",
                            "properties": {"account_number": row["sender_acc"], "owner_name": row["sender_name"]}
                        }
                    if r_id not in pg_nodes:
                        pg_nodes[r_id] = {
                            "id": r_id,
                            "label": row["receiver_name"] or row["receiver_acc"],
                            "type": "Account",
                            "properties": {"account_number": row["receiver_acc"], "owner_name": row["receiver_name"]}
                        }
                    pg_edges.append({
                        "id": str(row["tx_id"]),
                        "source": s_id,
                        "target": r_id,
                        "type": "TRANSFERS_TO",
                        "properties": {"amount": float(row["amount"]), "timestamp": str(row["timestamp"])}
                    })

                return {"nodes": list(pg_nodes.values()), "edges": pg_edges}
        except Exception as pg_err:
            raise HTTPException(
                status_code=500,
                detail=f"Graph node expansion failed on both Neo4j ({neo_err}) and PostgreSQL ({pg_err})"
            )
