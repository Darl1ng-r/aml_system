from fastapi import APIRouter, HTTPException, Depends
from fastapi.params import Depends as DependsClass
from pydantic import BaseModel
import json
import logging
import rapidfuzz
import uuid

logger = logging.getLogger(__name__)
from database.elasticsearch_db import get_async_elasticsearch_client
from database.redis_db import get_async_redis_client
from config import SANCTIONS_INDEX
from services.auth import get_current_user, RoleChecker, enforce_tenant_data_scope
from services.rate_limiter import RateLimiter

router = APIRouter(prefix="/api/v1/screening", tags=["Screening"])

from pydantic import BaseModel, Field, field_validator
from observability.sanitizer import sanitize_text

class ScreeningRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    date_of_birth: str | None = Field(None, max_length=10, pattern=r"^\d{4}-\d{2}-\d{2}$")
    threshold: float = Field(0.80, ge=0.50, le=1.00)

    @field_validator("name", mode="before")
    @classmethod
    def sanitize_name(cls, v: str) -> str:
        return sanitize_text(v)

def levenshtein_ratio(s1: str, s2: str) -> float:
    """
    Computes Levenshtein similarity ratio between s1 and s2 in range [0.0, 1.0]
    using the high-performance C-optimized rapidfuzz library.
    """
    s1, s2 = s1.lower().strip(), s2.lower().strip()
    max_len = len(s1) + len(s2)
    if max_len == 0:
        return 1.0
    dist = rapidfuzz.distance.Levenshtein.distance(s1, s2, weights=(1, 1, 2))
    return (max_len - dist) / max_len

async def perform_sanctions_search(name: str, threshold: float, es) -> dict:
    """
    Core fuzzy sanctions search logic against Elasticsearch.
    """
    # Search Elasticsearch sanctions index using fuzzy match
    query = {
        "query": {
            "match": {
                "name": {
                    "query": name,
                    "fuzziness": "AUTO",
                    "prefix_length": 2
                }
            }
        }
    }
    
    response = await es.search(index=SANCTIONS_INDEX, body=query, size=5)
    hits = response.get("hits", {}).get("hits", [])
    
    if not hits:
        return {
            "match_found": False,
            "score": 0.0,
            "source_list": None,
            "matched_entry": None
        }
        
    # Select best hit and compute exact string similarity ratio
    best_hit = hits[0]
    source = best_hit["_source"]
    matched_name = source.get("name", "")
    
    similarity_score = levenshtein_ratio(name, matched_name)
    match_found = similarity_score >= threshold
    
    return {
        "match_found": match_found,
        "score": round(similarity_score, 2),
        "source_list": source.get("source_list", "Unknown List"),
        "matched_entry": {
            "name": matched_name,
            "reason": f"Fuzzy similarity match of {int(similarity_score * 100)}%"
        }
    }

async def perform_pep_search(name: str, threshold: float, es, tenant_id: str | None = None) -> dict:
    """
    Dedicated Politically Exposed Persons (PEP) database search & tiering evaluation.
    """
    from config import PEP_INDEX
    try:
        query = {
            "query": {
                "match": {
                    "name": {
                        "query": name,
                        "fuzziness": "AUTO",
                        "prefix_length": 2
                    }
                }
            }
        }
        response = await es.search(index=PEP_INDEX, body=query, size=5)
        hits = response.get("hits", {}).get("hits", [])

        if hits:
            best_hit = hits[0]["_source"]
            matched_name = best_hit.get("name", "")
            similarity_score = levenshtein_ratio(name, matched_name)

            if similarity_score >= threshold:
                return {
                    "match_found": True,
                    "score": round(similarity_score, 2),
                    "pep_tier": best_hit.get("pep_tier", "TIER_2_GOVERNMENT_OFFICIAL"),
                    "position": best_hit.get("position", "Senior Official"),
                    "country": best_hit.get("country", "GLOBAL"),
                    "rca_flag": best_hit.get("rca_flag", False),
                    "source_list": best_hit.get("source_database", "FATF PEP Register"),
                    "matched_entry": {
                        "name": matched_name,
                        "edd_required": True,
                        "recommendation": "Enhanced Due Diligence (EDD) Required — Source of Wealth verification mandatory."
                    }
                }
    except Exception as e:
        logger.warning(f"Elasticsearch PEP search bypass/fallback: {e}")

    # Database Fallback for PEP entities (tenant-scoped to prevent cross-tenant data leakage)
    try:
        from database.postgres import get_async_db_read_conn
        async with get_async_db_read_conn(tenant_id=tenant_id) as conn:
            search_pattern = f"%{name.strip()}%"
            if tenant_id:
                try:
                    t_uuid = uuid.UUID(str(tenant_id))
                    rows = await conn.fetch(
                        """
                        SELECT name, pep_tier, position, country, rca_flag, source_database
                        FROM pep_entities
                        WHERE (tenant_id = $1 OR tenant_id IS NULL)
                          AND is_active = true
                          AND (name ILIKE $2 OR $3 ILIKE '%' || name || '%')
                        LIMIT 100;
                        """,
                        t_uuid, search_pattern, name.strip()
                    )
                except ValueError:
                    rows = await conn.fetch(
                        """
                        SELECT name, pep_tier, position, country, rca_flag, source_database
                        FROM pep_entities
                        WHERE tenant_id IS NULL
                          AND is_active = true
                          AND (name ILIKE $1 OR $2 ILIKE '%' || name || '%')
                        LIMIT 100;
                        """,
                        search_pattern, name.strip()
                    )
            else:
                rows = await conn.fetch(
                    """
                    SELECT name, pep_tier, position, country, rca_flag, source_database
                    FROM pep_entities
                    WHERE tenant_id IS NULL
                      AND is_active = true
                      AND (name ILIKE $1 OR $2 ILIKE '%' || name || '%')
                    LIMIT 100;
                    """,
                    search_pattern, name.strip()
                )

            for row in rows:
                p_name = row["name"]
                sim = levenshtein_ratio(name, p_name)
                if sim >= threshold:
                    return {
                        "match_found": True,
                        "score": round(sim, 2),
                        "pep_tier": row["pep_tier"],
                        "position": row["position"],
                        "country": row["country"],
                        "rca_flag": row["rca_flag"],
                        "source_list": row["source_database"],
                        "matched_entry": {
                            "name": p_name,
                            "edd_required": True,
                            "recommendation": "Enhanced Due Diligence (EDD) Required — Source of Wealth verification mandatory."
                        }
                    }
    except Exception as e:
        logger.warning(f"PostgreSQL PEP query fallback bypass: {e}")

    return {
        "match_found": False,
        "score": 0.0,
        "pep_tier": None,
        "source_list": None,
        "matched_entry": None
    }


@router.post("/search")
async def search_sanctions_and_pep(
    payload: ScreeningRequest, 
    es=Depends(get_async_elasticsearch_client), 
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    """
    Multi-tiered identity screening querying both:
      1. Global Sanctions Blocklists (OFAC, UN, EU) -> Mandatory Immediate Freeze
      2. Politically Exposed Persons (PEP) Tiering Database -> Enhanced Due Diligence (EDD)
    """
    tenant_id = enforce_tenant_data_scope(current_user)
    cache_key = f"screening:combined:{tenant_id}:{payload.name.lower().strip()}:{payload.threshold}"
    try:
        redis_client = await get_async_redis_client()
        cached_result = await redis_client.get(cache_key)
        if cached_result:
            return json.loads(cached_result)
    except Exception as e:
        logger.warning(f"Failed to query Redis cache: {e}")
        redis_client = None

    try:
        sanctions_res = await perform_sanctions_search(payload.name, payload.threshold, es)
        pep_res = await perform_pep_search(payload.name, payload.threshold, es, tenant_id=tenant_id)

        has_sanctions_hit = sanctions_res.get("match_found", False)
        has_pep_hit = pep_res.get("match_found", False)

        result = {
            "query_name": payload.name,
            "threshold": payload.threshold,
            "match_found": has_sanctions_hit or has_pep_hit,
            "sanctions_hit": sanctions_res,
            "pep_hit": pep_res,
            # Legacy compatibility fields
            "source_list": sanctions_res.get("source_list") if has_sanctions_hit else (pep_res.get("source_list") if has_pep_hit else "Clean"),
            "score": max(sanctions_res.get("score", 0.0), pep_res.get("score", 0.0)),
            "matched_entry": sanctions_res.get("matched_entry") or pep_res.get("matched_entry")
        }

        # Cache the successful result with a 1-hour TTL
        if redis_client:
            try:
                await redis_client.setex(cache_key, 3600, json.dumps(result))
            except Exception as e:
                logger.warning(f"Failed to save result to Redis cache: {e}")

        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Screening query failed: {str(e)}")

