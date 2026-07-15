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
