from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from database.elasticsearch_db import get_elasticsearch_client
from config import SANCTIONS_INDEX

router = APIRouter(prefix="/api/v1/screening", tags=["Screening"])

class ScreeningRequest(BaseModel):
    name: str
    date_of_birth: str | None = None
    threshold: float = 0.80

@router.post("/search")
def search_sanctions(payload: ScreeningRequest, es=Depends(get_elasticsearch_client)):
    try:
        # Construct search query. 
        # We try searching the name.phonetic field first. If the phonetic analysis 
        # plugin is missing and we fell back, we query name with fuzziness.
        query = {
            "query": {
                "bool": {
                    "should": [
                        {
                            "match": {
                                "name.phonetic": {
                                    "query": payload.name,
                                    "boost": 2.0
                                }
                            }
                        },
                        {
                            "match": {
                                "name": {
                                    "query": payload.name,
                                    "fuzziness": "AUTO",
                                    "prefix_length": 2
                                }
                            }
                        }
                    ]
                }
            }
        }
        
        response = es.search(index=SANCTIONS_INDEX, body=query, size=5)
        hits = response.get("hits", {}).get("hits", [])
        
        if not hits:
            return {
                "match_found": False,
                "score": 0.0,
                "source_list": None,
                "matched_entry": None
            }
            
        # Select best hit
        best_hit = hits[0]
        score = best_hit["_score"]
        source = best_hit["_source"]
        
        # Normalize score to an arbitrary [0.0, 1.0] range for matching
        # Elasticsearch scores can be > 1.0, so we normalize relative to max score or scale it
        normalized_score = min(score / 5.0, 1.0)
        
        match_found = normalized_score >= payload.threshold
        
        return {
            "match_found": match_found,
            "score": round(normalized_score, 2),
            "source_list": source.get("source_list", "Unknown List"),
            "matched_entry": {
                "name": source.get("name"),
                "reason": "Phonetic or fuzzy match detected in global database"
            }
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Screening query failed: {str(e)}")
