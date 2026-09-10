"""
JSON Web Key Set (JWKS) Endpoint
=================================
Publishes active asymmetric public keys in RFC 7517 compliant format for
microservices, downstream gateways, and frontend clients to verify RS256 JWTs.
"""

from fastapi import APIRouter
from services.secrets_manager import get_jwks

router = APIRouter(tags=["Cryptographic Keys"])


@router.get("/.well-known/jwks.json", summary="Get JSON Web Key Set (JWKS)")
def jwks():
    """
    Returns RFC 7517 compliant JWKS containing the active public RSA keys.
    Downstream systems can use this to verify signatures without access to private keys.
    """
    return get_jwks()
