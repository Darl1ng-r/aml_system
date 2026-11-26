"""
Graph Network Analytics, Corporate UBO Ownership Tree & Cross-Entity MDM Router
===============================================================================
Thin HTTP controller for graph network analytics, N-hop node expansion,
multi-layer corporate UBO tree resolution (>25%), and MDM link discovery.
All PostgreSQL SQL lives in `repositories/analytics_repo.py`.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel as _BaseModel, Field as _Field

from observability.sanitizer import sanitize_text as _sanitize_text
from repositories.analytics_repo import (
    create_ubo_edge_repo,
    expand_network_pg_fallback_repo,
    find_cross_entity_mdm_links_repo,
    list_corporate_ownership_edges_repo,
)
from services.auth import RoleChecker, enforce_tenant_data_scope
from services.network_analysis import run_network_analysis
from services.rate_limiter import RateLimiter

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api/v1/network", tags=["Network Analysis"])


@router.get("/analysis")
async def get_network_analysis(
    window_hours: int = Query(default=72, ge=1, le=720),
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Exposes graph network analytics (cycles, fan-in, fan-out, Brandes centrality)."""
    try:
        tenant_id = enforce_tenant_data_scope(current_user)
        return await run_network_analysis(tenant_id=str(tenant_id) if tenant_id else None, window_hours=window_hours)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Graph network analysis failed: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail="Graph network analysis failed.")


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
                edges.append(
                    {
                        "id": rel_id,
                        "source": src_id,
                        "target": dst_id,
                        "type": rel.type,
                        "properties": dict(rel),
                    }
                )

    return {"nodes": list(nodes.values()), "edges": edges}


async def _expand_neo4j(entity_id: str, tenant_id: str | None, hops: int = 2) -> dict:
    from database.neo4j_db import get_async_neo4j_driver

    driver = await get_async_neo4j_driver()
    safe_hops = max(1, min(int(hops), 3))
    query = f"""
    MATCH p = (start {{id: $entity_id}})-[r:TRANSFERS_TO|BELONGS_TO|OWNS_UBO*1..{safe_hops}]-(connected)
    WHERE ($tenant_id IS NULL OR (
        ALL(n IN nodes(p) WHERE n.tenant_id = $tenant_id)
        AND ALL(rel IN relationships(p) WHERE rel.tenant_id IS NULL OR rel.tenant_id = $tenant_id)
    ))
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
                    "risk_score": float(row.get("sender_risk") or 0.0),
                },
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
                    "risk_score": float(row.get("receiver_risk") or 0.0),
                },
            }
        tx_id = str(row["tx_id"])
        if tx_id not in seen_edges:
            seen_edges.add(tx_id)
            pg_edges.append(
                {
                    "id": tx_id,
                    "source": s_id,
                    "target": r_id,
                    "type": "TRANSFERS_TO",
                    "properties": {"amount": float(row["amount"]), "timestamp": str(row["timestamp"])},
                }
            )
    return {"nodes": list(pg_nodes.values()), "edges": pg_edges}


async def _expand_pg_fallback(entity_id: str, tenant_id: str | None, hops: int = 2) -> dict:
    resolved_entity, rows = await expand_network_pg_fallback_repo(
        entity_id=entity_id,
        tenant_id=tenant_id,
        hops=hops,
    )
    if resolved_entity is None:
        return {"nodes": [], "edges": [], "resolved_entity": None}
    parsed = _parse_pg_rows(rows)
    parsed["resolved_entity"] = resolved_entity
    return parsed


@router.get("/entities/{entity_id}/network")
@router.get("/nodes/{entity_id}/neighbors")
@router.get("/expand/{entity_id}")
async def expand_graph_node(
    entity_id: str,
    hops: int = Query(default=2, ge=1, le=3, description="Traversal depth in hops (1-3)"),
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR", "MLRO"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60)),
):
    """Dynamically expands a target graph node via Neo4j with automatic PostgreSQL fallback."""
    tenant_id = enforce_tenant_data_scope(current_user)
    neo_err = None
    if str(entity_id or "").strip().lower() not in ("", "auto", "default"):
        try:
            neo_res = await _expand_neo4j(entity_id, tenant_id, hops=hops)
            if neo_res and neo_res.get("nodes"):
                return neo_res
        except Exception as err:
            neo_err = err
            logger.info("Neo4j expansion unavailable (%s); executing in-engine PostgreSQL fallback...", err)

    try:
        return await _expand_pg_fallback(entity_id, tenant_id, hops=hops)
    except HTTPException:
        raise
    except Exception as pg_err:
        logger.error("Graph node expansion failed on Neo4j (%s) and PostgreSQL (%s)", neo_err, pg_err, exc_info=True)
        raise HTTPException(status_code=500, detail="Graph node expansion failed.")


# ── P2-4: Multi-Layer Corporate UBO Ownership Tree (>25%) & Cross-Entity MDM ──

class UBOEdgeCreateRequest(_BaseModel):
    parent_entity_name: str = _Field(..., min_length=2, max_length=200)
    parent_entity_type: str = _Field(default="PERSON", pattern=r"^(PERSON|COMPANY)$")
    child_company_name: str = _Field(..., min_length=2, max_length=200)
    ownership_pct: float = _Field(..., gt=0.0, le=100.0)
    jurisdiction: str = _Field(default="US", min_length=2, max_length=16)
    tax_id: str | None = _Field(default=None, max_length=80)
    verified_source: str = _Field(default="CORPORATE_REGISTRY", max_length=120)


@router.post("/ubo/edges", status_code=201)
async def create_ubo_ownership_edge(
    payload: UBOEdgeCreateRequest,
    current_user: dict = Depends(RoleChecker(["L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Records a corporate ownership edge for recursive >25% indirect UBO resolution."""
    tenant_id = enforce_tenant_data_scope(current_user)
    safe_parent = _sanitize_text(payload.parent_entity_name)
    safe_child = _sanitize_text(payload.child_company_name)
    if not safe_parent or not safe_child:
        raise HTTPException(status_code=422, detail="Entity names cannot be empty after sanitization.")
    edge_id = await create_ubo_edge_repo(
        tenant_id=str(tenant_id),
        safe_parent=safe_parent,
        parent_entity_type=payload.parent_entity_type,
        safe_child=safe_child,
        ownership_pct=payload.ownership_pct,
        jurisdiction=payload.jurisdiction.upper().strip(),
        tax_id=_sanitize_text(payload.tax_id) if payload.tax_id else None,
        verified_source=_sanitize_text(payload.verified_source),
    )
    return {
        "edge_id": str(edge_id),
        "parent_entity_name": safe_parent,
        "child_company_name": safe_child,
        "ownership_pct": payload.ownership_pct,
    }


@router.get("/ubo/tree/{company_name}")
async def get_ubo_ownership_tree(
    company_name: str,
    threshold_pct: float = Query(default=25.0, ge=1.0, le=100.0),
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Resolves multi-layer indirect equity ownership & split-ownership aggregation (>25% CDD threshold)."""
    from services.ubo_resolver import resolve_ubo_ownership_tree

    tenant_id = enforce_tenant_data_scope(current_user)
    edges = await list_corporate_ownership_edges_repo(tenant_id=str(tenant_id))
    return resolve_ubo_ownership_tree(edges, target_company=company_name, threshold_pct=threshold_pct)


@router.get("/mdm/links/{account_number}")
async def get_cross_entity_mdm_links(
    account_number: str,
    current_user: dict = Depends(RoleChecker(["L1_ANALYST", "L2_INVESTIGATOR", "ANALYST", "MLRO", "ADMIN", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=60, window=60)),
):
    """Uncovers hidden cross-entity MDM links sharing Tax IDs, device fingerprints, or beneficiary corridors."""
    tenant_id = enforce_tenant_data_scope(current_user)
    return await find_cross_entity_mdm_links_repo(
        tenant_id=str(tenant_id),
        account_number=account_number,
    )
