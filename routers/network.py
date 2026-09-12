from fastapi import APIRouter, Depends, HTTPException
from services.auth import RoleChecker
from services.rate_limiter import RateLimiter
from services.network_analysis import run_network_analysis

router = APIRouter(prefix="/api/v1/network", tags=["Network Analysis"])

@router.get("/analysis")
async def get_network_analysis(
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Exposes graph network analytics for compliance dashboards.
    Returns:
    - Circular money flow cycles (Tarjan's SCC).
    - Fan-In patterns (potential mules).
    - Fan-Out patterns (potential layering).
    - Intermediary middleman transit accounts (Brandes' Betweenness Centrality).
    """
    try:
        return await run_network_analysis()
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
    Dynamically expands a target graph node by fetching its 2-hop connected sub-network from Neo4j.
    """
    from database.neo4j_db import get_async_neo4j_driver
    try:
        driver = await get_async_neo4j_driver()
        query = """
        MATCH (start {id: $entity_id})-[r:TRANSFERS_TO|BELONGS_TO|OWNS_UBO*1..2]-(connected)
        RETURN start, r, connected
        LIMIT 50;
        """
        async with driver.session() as session:
            result = await session.run(query, entity_id=entity_id)
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
                s_type = list(s_node.labels)[0] if s_node.labels else "Account"
                nodes[s_id] = {"id": s_id, "label": s_label, "type": s_type, "properties": dict(s_node)}

            if c_node:
                c_id = c_node.get("id", str(c_node.element_id))
                c_label = c_node.get("account_number") or c_node.get("name") or c_id
                c_type = list(c_node.labels)[0] if c_node.labels else "Account"
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
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Graph node expansion failed: {str(e)}")
