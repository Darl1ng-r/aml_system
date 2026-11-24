"""
Cross-Page Topbar Parity & Seamless Navigation Regression Tests
================================================================
Ensures all 14 AML Sentinel workspace pages share:
  1. Identical versioned asset URLs (style.css, api-client.js, sentinel-shell.js)
  2. Pixel-identical pre-rendered 3-zone topbar HTML (including Frame-0 Search ⌘K & Bell)
  3. Zero Investigations-only controls inside <header> (moved to .case-context-strip)
  4. Zero conflicting opacity:0 sentinelPageEnter animation + frozen sentinel-topbar View Transition
  5. Immutable Cache-Control headers on versioned /static/*?v=... responses
"""

import re
import httpx
import pytest

from main import app

WORKSPACE_PAGES = [
    ("static/executive-dashboard.html", "/dashboard/executive"),
    ("static/triage.html", "/alerts/triage"),
    ("static/index.html", "/dashboard"),
    ("static/network.html", "/network"),
    ("static/customer-360.html", None),
    ("static/sar-editor.html", None),
    ("static/sar-queue.html", None),
    ("static/compliance-ops.html", None),
    ("static/rules-admin.html", None),
    ("static/ml-governance.html", None),
    ("static/risk-appetite.html", None),
    ("static/audit-vault.html", None),
    ("static/users-admin.html", None),
    ("static/system-health.html", None),
]


def _extract_header_html(page_html: str) -> str:
    m = re.search(r"<header\b[^>]*>(.*?)</header>", page_html, re.S)
    assert m is not None, "Missing <header> element"
    return m.group(1)


def _normalize_header_for_parity(header_inner: str) -> str:
    # Normalize active pill class and whitespace so all 14 pages can be compared byte-for-byte
    norm = header_inner.replace('class="nav-pill active"', 'class="nav-pill"')
    norm = re.sub(r"\s+", " ", norm).strip()
    return norm


def test_all_14_workspace_pages_share_identical_versioned_assets():
    css_versions = set()
    api_versions = set()
    shell_versions = set()

    for path, _ in WORKSPACE_PAGES:
        txt = open(path, encoding="utf-8").read()
        m_css = re.search(r'/static/style\.css\?v=([^"]+)', txt)
        m_api = re.search(r'/static/api-client\.js\?v=([^"]+)', txt)
        m_sh = re.search(r'/static/sentinel-shell\.js\?v=([^"]+)', txt)
        assert m_css, f"{path} missing versioned style.css"
        assert m_api, f"{path} missing versioned api-client.js"
        assert m_sh, f"{path} missing versioned sentinel-shell.js"
        css_versions.add(m_css.group(1))
        api_versions.add(m_api.group(1))
        shell_versions.add(m_sh.group(1))
        # Ensure api-client.js is never duplicated twice on the same page
        assert len(re.findall(r'/static/api-client\.js', txt)) == 1, f"Duplicate api-client.js in {path}"

    assert len(css_versions) == 1, f"Mismatched style.css versions across pages: {css_versions}"
    assert len(api_versions) == 1, f"Mismatched api-client.js versions across pages: {api_versions}"
    assert len(shell_versions) == 1, f"Mismatched sentinel-shell.js versions across pages: {shell_versions}"


def test_all_14_workspace_pages_render_byte_identical_topbar_structure():
    canonical = None
    for path, expected_active in WORKSPACE_PAGES:
        txt = open(path, encoding="utf-8").read()
        hdr = _extract_header_html(txt)

        # Every page must pre-render Frame-0 topbar controls directly in HTML (no late JS pop-in)
        assert 'id="sentinel-cmdk-trigger"' in hdr, f"{path} missing pre-rendered Search ⌘K trigger"
        assert 'id="sentinel-notif-bell"' in hdr, f"{path} missing pre-rendered Notification bell"
        assert 'id="sentinel-notif-badge"' in hdr, f"{path} missing pre-rendered Notification badge"
        assert 'id="btn-sentinel-modules"' in hdr, f"{path} missing unified Modules trigger"
        assert 'id="sentinel-modules-menu"' in hdr, f"{path} missing unified Modules menu"
        assert 'id="sentinel-user-avatar"' in hdr, f"{path} missing profile icon"

        # Active pill check
        active_pills = re.findall(r'<a href="([^"]+)" class="nav-pill active"', hdr)
        if expected_active is None:
            assert active_pills == [], f"{path} should not mark a core pill active: {active_pills}"
        else:
            assert active_pills == [expected_active], f"{path} expected active={expected_active}, got {active_pills}"

        norm = _normalize_header_for_parity(hdr)
        if canonical is None:
            canonical = norm
        else:
            assert norm == canonical, f"Topbar markup diverged on {path}!"


def test_investigations_keeps_case_context_in_strip_not_topbar():
    txt = open("static/index.html", encoding="utf-8").read()
    hdr = _extract_header_html(txt)

    # Topbar must NOT contain Investigations-only elements
    assert "topbar-case-id" not in hdr
    assert "topbar-case-crumb" not in hdr
    assert "queue-position-display" not in hdr
    assert "shortcuts-modal" not in hdr

    # Investigations body MUST retain all DOM IDs inside .case-context-strip so app.js works seamlessly
    body_after_hdr = txt.split("</header>", 1)[1]
    assert 'class="case-context-strip"' in body_after_hdr
    assert 'id="topbar-case-id"' in body_after_hdr
    assert 'id="topbar-case-crumb"' in body_after_hdr
    assert 'id="queue-position-display"' in body_after_hdr
    assert "openModal('shortcuts-modal')" in body_after_hdr
    # External vis-network.min.css must be non-render-blocking
    assert 'vis-network.min.css" rel="stylesheet" media="print"' in txt


def test_style_css_eliminates_flicker_animation_and_pins_view_transition_topbar():
    css = open("static/style.css", encoding="utf-8").read()
    assert "@view-transition" in css
    assert "view-transition-name: sentinel-topbar" in css
    assert "::view-transition-old(sentinel-topbar)" in css
    assert "sentinelPageEnter" not in css, "Conflicting opacity:0 sentinelPageEnter animation must stay removed"
    assert ".sentinel-page-scroll" in css
    assert ".sentinel-shell-btn" in css


@pytest.mark.asyncio
async def test_versioned_static_assets_emit_immutable_cache_headers():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        r_ver = await client.get("/static/style.css?v=20261124-u1")
        assert r_ver.status_code == 200
        assert "immutable" in r_ver.headers.get("cache-control", "")
        assert "max-age=31536000" in r_ver.headers.get("cache-control", "")

        r_unver = await client.get("/static/style.css")
        assert r_unver.status_code == 200
        assert "max-age=300" in r_unver.headers.get("cache-control", "")
