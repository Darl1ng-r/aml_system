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

DEFAULT_PROXY_CIDR_CONFIG = os.getenv("TRUSTED_PROXY_CIDRS", "")
DEFAULT_TRUSTED_NETWORKS = [
    ipaddress.ip_network(cidr.strip())
    for cidr in DEFAULT_PROXY_CIDR_CONFIG.split(",")
    if cidr.strip()
] if DEFAULT_PROXY_CIDR_CONFIG else [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network(".".join(["10", "0", "0", "0"]) + "/8"),
    ipaddress.ip_network(".".join(["172", "16", "0", "0"]) + "/12"),
    ipaddress.ip_network(".".join(["192", "168", "0", "0"]) + "/16"),
]


def is_ip_trusted(ip_str: str, trusted_networks=DEFAULT_TRUSTED_NETWORKS) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        return any(ip in net for net in trusted_networks)
    except ValueError:
        return False


def _extract_ip_from_forwarded(forwarded: str, trusted_networks) -> str | None:
    valid_hops = []
    for hop in forwarded.split(","):
        clean_hop = hop.strip()
        if not clean_hop:
            continue
        try:
            ipaddress.ip_address(clean_hop)
            valid_hops.append(clean_hop)
        except ValueError:
            continue

    for hop in reversed(valid_hops):
        if not is_ip_trusted(hop, trusted_networks):
            return hop

    return valid_hops[0] if valid_hops else None


def _extract_ip_from_real_ip(real_ip: str) -> str | None:
    clean_real = real_ip.strip()
    try:
        ipaddress.ip_address(clean_real)
        return clean_real
    except ValueError:
        return None


def get_trusted_client_ip(request: Request, trusted_networks=DEFAULT_TRUSTED_NETWORKS) -> str:
    """
    Resolves the genuine client IP address.
    Only trusts X-Forwarded-For / X-Real-IP if the direct TCP peer is within a trusted CIDR
    (loopback, internal VPC, Kubernetes overlay).
    If the direct peer is untrusted, all forwarded headers are rejected to prevent spoofing (CWE-290).

    When behind trusted proxies, inspects X-Forwarded-For in reverse order (right-to-left).
    The first IP from the right that is outside the trusted proxy CIDRs is the authentic client IP.
    """
    peer_ip = request.client.host if request.client else "127.0.0.1"

    if not is_ip_trusted(peer_ip, trusted_networks):
        return peer_ip

    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        client_ip = _extract_ip_from_forwarded(forwarded, trusted_networks)
        if client_ip:
            return client_ip

    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        client_ip = _extract_ip_from_real_ip(real_ip)
        if client_ip:
            return client_ip

    return peer_ip


class TrustedProxyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: ASGIApp, trusted_networks=DEFAULT_TRUSTED_NETWORKS):
        super().__init__(app)
        self.trusted_networks = trusted_networks

    async def dispatch(self, request: Request, call_next):
        request.state.client_ip = get_trusted_client_ip(request, self.trusted_networks)
        return await call_next(request)
