from fastapi import APIRouter, HTTPException, Depends
from fastapi.params import Depends as DependsClass
from pydantic import BaseModel
from database.elasticsearch_db import get_async_elasticsearch_client
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
    """
    s1, s2 = s1.lower().strip(), s2.lower().strip()
    rows = len(s1) + 1
    cols = len(s2) + 1
    dist = [[0 for _ in range(cols)] for _ in range(rows)]
    for i in range(1, rows):
        dist[i][0] = i
    for j in range(1, cols):
        dist[0][j] = j
        
    for col in range(1, cols):
        for row in range(1, rows):
            if s1[row-1] == s2[col-1]:
                cost = 0
            else:
                cost = 2
            dist[row][col] = min(
                dist[row-1][col] + 1,      # deletion
                dist[row][col-1] + 1,      # insertion
                dist[row-1][col-1] + cost  # substitution
            )
            
    max_len = len(s1) + len(s2)
    if max_len == 0:
        return 1.0
    return (max_len - dist[len(s1)][len(s2)]) / max_len

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
    try:
        return await perform_sanctions_search(payload.name, payload.threshold, es)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Screening query failed: {str(e)}")

