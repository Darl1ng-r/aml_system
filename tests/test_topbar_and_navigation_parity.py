"""
Single Shared Topbar Component & Seamless Navigation Regression Tests
=====================================================================
Ensures all 14 AML Sentinel workspace pages use ONE single shared topbar component
(`static/partials/topbar.html`) composed server-side in `main.py` with:
  1. Zero duplicated `<header>` markup in any of the 14 workspace HTML source files
  2. Strict HTML revalidation (`Cache-Control: private, no-cache, must-revalidate` + `ETag` + `304`)
     so browsers never serve stale cached HTML on one tab while serving fresh HTML on another
  3. 100% byte-identical rendered topbar markup and unified versioned asset URLs across all 14 live routes
  4. Zero Investigations-only controls inside `<header>` (kept in `.case-context-strip`)
  5. Preserved OWASP `X-Frame-Options: DENY` / `frame-ancestors 'none'` + immutable versioned static caching
"""

import re
import uuid
import httpx
import pytest

from main import app, SENTINEL_ASSET_VERSION
from services.auth import create_access_token

WORKSPACE_ROUTES = [
    ("/dashboard/executive", "static/executive-dashboard.html", "/dashboard/executive", "header-nav"),
    ("/alerts/triage", "static/triage.html", "/alerts/triage", "triage-nav"),
    ("/dashboard", "static/index.html", "/dashboard", "topbar"),
    ("/network", "static/network.html", "/network", "header-nav"),
    ("/customers", "static/customer-360.html", None, "header-nav"),
    ("/sar/editor", "static/sar-editor.html", None, "header-nav"),
    ("/sar/queue", "static/sar-queue.html", None, "header-nav"),
    ("/compliance/ops", "static/compliance-ops.html", None, "navbar"),
    ("/admin/rules", "static/rules-admin.html", None, "rules-nav"),
    ("/ml/governance", "static/ml-governance.html", None, "header-nav"),
    ("/settings/risk-appetite", "static/risk-appetite.html", None, "header-nav"),
    ("/audit/logs", "static/audit-vault.html", None, "header-nav"),
    ("/admin/users", "static/users-admin.html", None, "users-nav"),
    ("/admin/health", "static/system-health.html", None, "header-nav"),
]


def _make_session_cookie() -> dict[str, str]:
    token = create_access_token(
        {
            "sub": "topbar.verifier",
            "username": "topbar.verifier",
            "role": "ADMIN",
            "tenant_id": "00000000-0000-0000-0000-000000000001",
            "id": str(uuid.uuid4()),
        }
    )
    return {"access_token": token}


def _extract_header_html(page_html: str) -> str:
    m = re.search(r"<header\b[^>]*>(.*?)</header>", page_html, re.S)
    assert m is not None, "Missing rendered <header> element"
    return m.group(1)


def _normalize_header_for_parity(header_inner: str) -> str:
    norm = header_inner.replace('class="nav-pill active"', 'class="nav-pill"')
    norm = norm.replace(' aria-current="page"', "")
    norm = re.sub(r"\s+", " ", norm).strip()
    return norm


def test_all_14_source_html_files_use_single_shared_topbar_slot():
    """Zero hardcoded <header> copies may exist in any of the 14 workspace HTML source files."""
    partial = open("static/partials/topbar.html", encoding="utf-8").read()
    assert "<header class=\"{{HEADER_CLASS}}\">" in partial
    assert 'id="sentinel-cmdk-trigger"' in partial
    assert 'id="sentinel-notif-bell"' in partial
    assert 'id="btn-sentinel-modules"' in partial

    for _, path, _, _ in WORKSPACE_ROUTES:
        txt = open(path, encoding="utf-8").read()
        assert "<header" not in txt, f"Found duplicated hardcoded <header> in {path}!"
        assert "<!-- @SENTINEL_TOPBAR -->" in txt, f"Missing <!-- @SENTINEL_TOPBAR --> slot in {path}"
        assert "<!-- @SENTINEL_HEAD_ASSETS -->" in txt, f"Missing <!-- @SENTINEL_HEAD_ASSETS --> slot in {path}"


@pytest.mark.asyncio
async def test_all_14_live_routes_render_byte_identical_topbar_with_no_stale_cache():
    """All 14 live routes must serve the exact shared topbar, unified asset version, no-cache headers, and 304 ETag."""
    cookies = _make_session_cookie()
    transport = httpx.ASGITransport(app=app)
    canonical_header = None

    async with httpx.AsyncClient(transport=transport, base_url="http://test", cookies=cookies) as client:
        for route, _, expected_active, expected_hdr_class in WORKSPACE_ROUTES:
            resp = await client.get(route)
            assert resp.status_code == 200, f"{route} returned {resp.status_code}"

            # Anti-stale-HTML caching & OWASP clickjacking headers
            cc = resp.headers.get("cache-control", "")
            assert "no-cache" in cc and "must-revalidate" in cc, f"{route} missing no-cache header: {cc}"
            assert resp.headers.get("x-frame-options") == "DENY"
            assert "frame-ancestors 'none'" in resp.headers.get("content-security-policy", "")
            etag = resp.headers.get("etag")
            assert etag, f"{route} missing ETag"

            html = resp.text
            assert "<!-- @SENTINEL_TOPBAR -->" not in html
            assert "<!-- @SENTINEL_HEAD_ASSETS -->" not in html
            assert f"/static/style.css?v={SENTINEL_ASSET_VERSION}" in html
            assert f"/static/api-client.js?v={SENTINEL_ASSET_VERSION}" in html
            assert f"/static/sentinel-shell.js?v={SENTINEL_ASSET_VERSION}" in html
            assert f'<header class="{expected_hdr_class}">' in html

            hdr = _extract_header_html(html)
            active_pills = re.findall(r'<a href="([^"]+)" class="nav-pill active" aria-current="page"', hdr)
            if expected_active is None:
                assert active_pills == [], f"{route} unexpectedly marked active pills: {active_pills}"
            else:
                assert active_pills == [expected_active], f"{route} expected active={expected_active}, got {active_pills}"

            norm = _normalize_header_for_parity(hdr)
            if canonical_header is None:
                canonical_header = norm
            else:
                assert norm == canonical_header, f"Rendered topbar diverged on live route {route}!"

            # Conditional ETag revalidation must return 304 Not Modified
            resp_304 = await client.get(route, headers={"If-None-Match": etag})
            assert resp_304.status_code == 304, f"{route} failed conditional ETag 304 check"


@pytest.mark.asyncio
async def test_investigations_keeps_case_context_in_strip_not_topbar():
    cookies = _make_session_cookie()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test", cookies=cookies) as client:
        resp = await client.get("/dashboard")
        assert resp.status_code == 200
        html = resp.text

    hdr = _extract_header_html(html)
    assert "topbar-case-id" not in hdr
    assert "topbar-case-crumb" not in hdr
    assert "queue-position-display" not in hdr
    assert "shortcuts-modal" not in hdr

    body_after_hdr = html.split("</header>", 1)[1]
    assert 'class="case-context-strip"' in body_after_hdr
    assert 'id="topbar-case-id"' in body_after_hdr
    assert 'id="topbar-case-crumb"' in body_after_hdr
    assert 'id="queue-position-display"' in body_after_hdr
    assert "openModal('shortcuts-modal')" in body_after_hdr
    assert 'vis-network.min.css" rel="stylesheet" media="print"' in html


def test_style_css_eliminates_flicker_animation_and_pins_view_transition_topbar():
    css = open("static/style.css", encoding="utf-8").read()
    assert "@view-transition" in css
    assert "view-transition-name: sentinel-topbar" in css
    assert "::view-transition-old(sentinel-topbar)" in css
    assert "sentinelPageEnter" not in css, "Conflicting opacity:0 sentinelPageEnter animation must stay removed"
    assert ".sentinel-page-scroll" in css
    assert ".sentinel-shell-btn" in css
    assert "#sentinel-notif-bell" in css


@pytest.mark.asyncio
async def test_versioned_static_assets_emit_immutable_cache_headers():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r_ver = await client.get(f"/static/style.css?v={SENTINEL_ASSET_VERSION}")
        assert r_ver.status_code == 200
        assert "immutable" in r_ver.headers.get("cache-control", "")
        assert "max-age=31536000" in r_ver.headers.get("cache-control", "")

        r_unver = await client.get("/static/style.css")
        assert r_unver.status_code == 200
        assert "max-age=300" in r_unver.headers.get("cache-control", "")
