"""
JSON Web Key Set (JWKS) Endpoint
=================================
Publishes active + grace-period asymmetric public keys in RFC 7517 format
with Cache-Control, strong ETag, and HTTP 304 Not Modified support (P3-05).
"""

import hashlib
import json
from typing import Optional

from fastapi import APIRouter, Depends, Header, Response
from services.rate_limiter import RateLimiter
from services.secrets_manager import get_jwks

router = APIRouter(tags=["Cryptographic Keys"])


@router.get("/.well-known/jwks.json", summary="Get JSON Web Key Set (JWKS)")
def jwks(
    response: Response,
    if_none_match: Optional[str] = Header(None),
    _rate_limit=Depends(RateLimiter(limit=120, window=60, ip_only=True)),
):
    """
    Returns RFC 7517 compliant JWKS containing active & grace-period public RSA keys
    with Cache-Control, ETag, and conditional 304 Not Modified handling.
    """
    payload = get_jwks()
    etag_val = f'"{hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:16]}"'
    cache_headers = {
        "Cache-Control": "public, max-age=300",
        "ETag": etag_val,
    }
    if if_none_match and etag_val in {t.strip().lstrip("W/") for t in if_none_match.split(",")}:
        return Response(status_code=304, headers=cache_headers)

    response.headers.update(cache_headers)
    return payload
