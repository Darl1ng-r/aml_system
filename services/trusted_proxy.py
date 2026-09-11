"""
Trusted Proxy & CIDR Header Resolution Middleware
=================================================
Validates upstream proxy IPs against trusted CIDR networks (loopback, private VPCs)
before trusting X-Forwarded-For or X-Real-IP headers. Neutralizes rate limiter
spoofing and IP-based denial-of-service vectors.
"""

import ipaddress
import logging
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from fastapi import Request

logger = logging.getLogger(__name__)

DEFAULT_TRUSTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_ip_trusted(ip_str: str, trusted_networks=DEFAULT_TRUSTED_NETWORKS) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in trusted_networks)
    except ValueError:
        return False


def get_trusted_client_ip(request: Request, trusted_networks=DEFAULT_TRUSTED_NETWORKS) -> str:
    """
    Resolves the genuine client IP address.
    Only trusts X-Forwarded-For / X-Real-IP if the direct TCP peer is within a trusted CIDR
    (loopback, internal VPC, Kubernetes overlay).
    If the direct peer is untrusted, all forwarded headers are rejected to prevent spoofing (CWE-290).
    When behind a trusted proxy, returns the first validated client IP from X-Forwarded-For.
    """
    peer_ip = request.client.host if request.client else "127.0.0.1"

    if is_ip_trusted(peer_ip, trusted_networks):
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            hops = [h.strip() for h in forwarded.split(",") if h.strip()]
            for hop in hops:
                try:
                    ipaddress.ip_address(hop)
                    return hop
                except ValueError:
                    continue

        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            clean_real = real_ip.strip()
            try:
                ipaddress.ip_address(clean_real)
                return clean_real
            except ValueError:
                pass

    return peer_ip


class TrustedProxyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, trusted_networks=DEFAULT_TRUSTED_NETWORKS):
        super().__init__(app)
        self.trusted_networks = trusted_networks

    async def dispatch(self, request: Request, call_next):
        request.state.client_ip = get_trusted_client_ip(request, self.trusted_networks)
        return await call_next(request)
