"""
IAM Client & Downstream Auth Validator
======================================
Consolidated into services.auth to eliminate the "Fake Microservice" (port 8001)
and provide unified in-process identity resolution without network hops or serialization.
Re-exported here for full backward compatibility.
"""

from services.auth import (
    UserClaims,
    DownstreamAuthValidator,
    default_validator,
    get_current_user_claims,
)

__all__ = [
    "UserClaims",
    "DownstreamAuthValidator",
    "default_validator",
    "get_current_user_claims",
]

