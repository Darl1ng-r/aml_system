"""
Cloudflare Turnstile Bot Mitigation Service
============================================
Provides canonical server-side validation of Cloudflare Turnstile challenge tokens
to prevent credential stuffing and automated bot attacks on authentication endpoints.
"""

import logging
import httpx
from config import settings
from services.http_client import CircuitOpenError, request_with_resilience

logger = logging.getLogger(__name__)

TURNSTILE_SITEVERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"

# Official Cloudflare Turnstile always-pass test secret key (strictly local dev/test ONLY)
TURNSTILE_TEST_SECRET = "1x0000000000000000000000000000000AA"


async def verify_turnstile_token(token: str | None, remote_ip: str | None = None) -> bool:
    """
    Verifies a Turnstile CAPTCHA token against the Cloudflare siteverify API.
    - Hardened environments (production / prod / staging): strictly require
      settings.turnstile_secret_key and NEVER fall back to Cloudflare's always-pass
      test secret (fixes P0-05).
    - Development / test environments: permits local bypass when token is omitted
      or a mock token is supplied.
    """
    is_hardened = getattr(settings, "is_hardened", settings.is_production)
    secret = (getattr(settings, "turnstile_secret_key", "") or "").strip()

    if is_hardened:
        if not secret or secret == TURNSTILE_TEST_SECRET:
            logger.error(
                "CRITICAL: TURNSTILE_SECRET_KEY is missing or set to Cloudflare's always-pass test key "
                "in a hardened environment. Failing closed."
            )
            raise RuntimeError("TURNSTILE_SECRET_KEY must be configured with a live secret in production/staging.")
    else:
        secret = secret or TURNSTILE_TEST_SECRET

    # In local development or testing mode, allow bypass if token is mock or omitted
    if not token:
        if (not is_hardened) and (settings.environment in {"development", "test"} or settings.allow_offline_dev):
            return True
        return False

    if token in {"dummy_turnstile_token", "test_token", "cf-test-passed"} and not is_hardened:
        return True

    payload = {
        "secret": secret,
        "response": token,
    }
    if remote_ip:
        payload["remoteip"] = remote_ip

    try:
        resp = await request_with_resilience(
            "POST",
            TURNSTILE_SITEVERIFY_URL,
            target="cloudflare_turnstile",
            timeout=httpx.Timeout(connect=1.5, read=3.0, write=2.0, pool=1.5),
            follow_redirects=False,
            retries=1,
            data=payload,
        )
        if resp.status_code == 200:
            data = resp.json()
            success = bool(data.get("success", False))
            if not success:
                logger.warning("Turnstile verification failed: %s", data.get("error-codes", []))
            return success
        logger.warning("Turnstile siteverify endpoint returned HTTP %s", resp.status_code)
        return False
    except (CircuitOpenError, Exception) as exc:
        logger.warning("Turnstile siteverify unreachable: %s", exc)
        if not is_hardened:
            return True
        return False
