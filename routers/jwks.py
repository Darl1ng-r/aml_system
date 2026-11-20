"""
JSON Web Key Set (JWKS) Endpoint
=================================
Publishes active asymmetric public keys in RFC 7517 compliant format for
microservices, downstream gateways, and frontend clients to verify RS256 JWTs.
"""

import hashlib
import json
from fastapi import APIRouter, Response
from services.secrets_manager import get_jwks

router = APIRouter(tags=["Cryptographic Keys"])


@router.get("/.well-known/jwks.json", summary="Get JSON Web Key Set (JWKS)")
def jwks(response: Response):
    """
    Returns RFC 7517 compliant JWKS containing the active public RSA keys
    with HTTP caching headers (Cache-Control + ETag) for downstream verifiers.
    """
    payload = get_jwks()
    etag = hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()[:16]
    response.headers["Cache-Control"] = "public, max-age=300"
    response.headers["ETag"] = f'"{etag}"'
    return payload
