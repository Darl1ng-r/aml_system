from fastapi import APIRouter, HTTPException, Depends
from fastapi.params import Depends as DependsClass
from pydantic import BaseModel
import json
import rapidfuzz
from database.elasticsearch_db import get_async_elasticsearch_client
from database.redis_db import get_async_redis_client
from config import SANCTIONS_INDEX
from services.auth import get_current_user, RoleChecker
from services.rate_limiter import RateLimiter

router = APIRouter(prefix="/api/v1/screening", tags=["Screening"])

class ScreeningRequest(BaseModel):
    name: str
    date_of_birth: str | None = None
    threshold: float = 0.80

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

@router.post("/search")
async def search_sanctions(
    payload: ScreeningRequest, 
    es=Depends(get_async_elasticsearch_client), 
    current_user: dict = Depends(RoleChecker(["ADMIN", "ANALYST", "AUDITOR"])),
    _rate_limit=Depends(RateLimiter(limit=30, window=60))
):
    # Check Redis cache first to avoid ES lookup and Levenshtein computation
    cache_key = f"sanctions:screening:{payload.name.lower().strip()}:{payload.threshold}"
    try:
        redis_client = await get_async_redis_client()
        cached_result = await redis_client.get(cache_key)
        if cached_result:
            return json.loads(cached_result)
    except Exception as e:
        logger.warning(f"Failed to query Redis cache: {e}")
        redis_client = None

    try:
        result = await perform_sanctions_search(payload.name, payload.threshold, es)
        
        # Cache the successful result with a 1-hour TTL
        if redis_client:
            try:
                await redis_client.setex(cache_key, 3600, json.dumps(result))
            except Exception as e:
                logger.warning(f"Failed to save result to Redis cache: {e}")
                
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Screening query failed: {str(e)}")

