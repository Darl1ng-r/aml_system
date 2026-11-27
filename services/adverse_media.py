"""
Live Adverse Media NLP Screening & Entity Disambiguation Service (P2-5)
========================================================================
Upgrades negative news screening from a static keyword check into a live
OSINT risk intelligence engine:
  - 7 Financial-Crime Taxonomies (FINANCIAL_CRIME, SANCTIONS_EVASION, CORRUPTION,
    TERRORISM, NARCOTICS, REGULATORY_ENFORCEMENT, SHELL_COMPANY)
  - Sentence-Window Entity Disambiguation: Scores confidence (0.0-1.0) using
    proximity between the subject name and adverse predicates, jurisdiction/entity
    context boosting, and namesake false-positive suppression (sports/entertainment).
  - Live async GDELT 2.0 Global News API connector cached 6h in Redis with clean
    offline OSINT fallback when running in air-gapped sandboxes or pytest.
"""

import hashlib
import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import httpx

from config import settings
from database.redis_db import get_async_redis_client

logger = logging.getLogger("aml.adverse_media")

ADVERSE_TAXONOMIES: Dict[str, List[str]] = {
    "FINANCIAL_CRIME": ["money laundering", "fraud", "embezzlement", "tax evasion", "ponzi", "wire fraud", "structuring"],
    "SANCTIONS_EVASION": ["sanctions evasion", "ofac violation", "sanctions bypass", "sanctions breach", "sanctioned"],
    "CORRUPTION": ["bribery", "kickback", "corrupt", "extortion", "kleptocracy", "graft"],
    "TERRORISM": ["terrorist", "sanctions violation", "smuggling", "arms trafficking", "terror financing"],
    "NARCOTICS": ["drug cartel", "narcotics trafficking", "contraband", "fentanyl ring"],
    "REGULATORY_ENFORCEMENT": ["indicted", "consent order", "enforcement action", "doj charges", "sec charges", "fincen penalty"],
    "SHELL_COMPANY": ["shell company", "offshore shell", "nominee director", "beneficial ownership concealment", "panama papers"],
}

# Benign contexts that indicate a likely namesake false positive when no crime co-occurs nearby
BENIGN_NAMESAKE_MARKERS = (
    "championship", "touchdown", "box office", "concert tour", "premier league",
    "basketball", "grammy", "olympics", "movie premiere", "season finale",
)

OSINT_CACHE_TTL_SECONDS = 21600  # 6 hours


def evaluate_adverse_media_text(subject_name: str, article_text: str) -> Dict[str, Any]:
    """
    Evaluates an article snippet for co-occurrence of subject name and adverse risk taxonomies.
    Preserves backwards-compatible return contract while using expanded 7-category taxonomy.
    """
    if not subject_name or not article_text:
        return {"match_found": False, "matched_categories": [], "risk_score": 0.0}

    name_tokens = subject_name.lower().split()
    text_lower = article_text.lower()

    if not all(token in text_lower for token in name_tokens):
        return {"match_found": False, "matched_categories": [], "risk_score": 0.0}

    matched_categories = []
    for category, keywords in ADVERSE_TAXONOMIES.items():
        if any(kw in text_lower for kw in keywords):
            matched_categories.append(category)

    match_found = len(matched_categories) > 0
    risk_score = min(0.35 * len(matched_categories), 0.95) if match_found else 0.0

    return {
        "match_found": match_found,
        "subject_name": subject_name,
        "matched_categories": matched_categories,
        "risk_score": round(risk_score, 2),
        "edd_recommended": risk_score >= 0.60,
    }


def disambiguate_adverse_hit(
    subject_name: str,
    article_text: str,
    country: Optional[str] = None,
    entity_type: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Entity Disambiguation & Sentence-Window NLP Scorer (P2-5):
      - Splits text into sentences and measures whether the subject appears in the
        SAME sentence as an adverse predicate (high confidence) vs distant mention.
      - Applies jurisdiction/corporate context boost when `country` or corporate suffix matches.
      - Suppresses namesake false positives when benign sports/entertainment markers dominate.
    """
    base = evaluate_adverse_media_text(subject_name, article_text)
    if not base["match_found"]:
        return {
            **base,
            "disambiguation_confidence": 0.0,
            "same_sentence_match": False,
            "false_positive_suppressed": False,
        }

    text_lower = article_text.lower()
    name_tokens = [t for t in subject_name.lower().split() if len(t) > 1]
    sentences = [s.strip() for s in re.split(r"(?<=[.!?])\s+|\n+", text_lower) if s.strip()]

    same_sentence = False
    matched_excerpt = article_text[:240]
    all_matched_kws = [
        kw
        for cat in base["matched_categories"]
        for kw in ADVERSE_TAXONOMIES.get(cat, [])
    ]

    for sent in sentences:
        if all(tok in sent for tok in name_tokens) and any(kw in sent for kw in all_matched_kws):
            same_sentence = True
            matched_excerpt = sent[:260]
            break

    benign_hits = sum(1 for m in BENIGN_NAMESAKE_MARKERS if m in text_lower)
    confidence = 0.78 if same_sentence else 0.42

    if country and country.strip().lower() in text_lower:
        confidence += 0.10
    if entity_type and entity_type.upper() == "CORPORATE" and any(
        sfx in text_lower for sfx in ("ltd", "llc", "corp", "holdings", "inc", "s.a.", "gmbh")
    ):
        confidence += 0.07

    suppressed = False
    if benign_hits >= 1 and not same_sentence:
        confidence = max(0.05, confidence - 0.35 * benign_hits)
        suppressed = True

    confidence = round(min(0.99, max(0.0, confidence)), 2)
    adjusted_risk = round(base["risk_score"] * (1.0 if not suppressed else 0.25), 2)

    return {
        "match_found": not suppressed and confidence >= 0.40,
        "subject_name": subject_name,
        "matched_categories": base["matched_categories"],
        "risk_score": adjusted_risk,
        "edd_recommended": (not suppressed) and adjusted_risk >= 0.60,
        "disambiguation_confidence": confidence,
        "same_sentence_match": same_sentence,
        "false_positive_suppressed": suppressed,
        "excerpt": matched_excerpt,
    }


async def _fetch_gdelt_articles(subject_name: str, max_articles: int = 8) -> tuple[List[Dict[str, Any]], bool]:
    """
    Queries live GDELT 2.0 Doc API via pooled httpx + circuit breaker.
    Returns (articles, had_error) so transient outages are NEVER negative-cached for 6 hours.
    """
    from services.http_client import CircuitOpenError, is_outbound_egress_allowed, request_with_resilience

    if os.getenv("PYTEST_CURRENT_TEST") or not is_outbound_egress_allowed("gdelt_osint"):
        return [], True

    query_expr = f'"{subject_name}" (laundering OR fraud OR sanctions OR bribery OR indictment OR offshore)'
    params = {
        "query": query_expr,
        "mode": "ArtList",
        "maxrecords": str(max(1, min(int(max_articles), 20))),
        "format": "json",
        "sort": "DateDesc",
    }
    try:
        resp = await request_with_resilience(
            "GET",
            settings.adverse_media_api_url,
            target="gdelt_osint",
            timeout=httpx.Timeout(connect=1.5, read=3.0, write=2.0, pool=1.5),
            follow_redirects=False,
            retries=1,
            params=params,
        )
        if resp.status_code != 200:
            return [], True
        data = resp.json()
        return list(data.get("articles") or []), False
    except (CircuitOpenError, Exception) as exc:
        logger.debug("GDELT OSINT lookup skipped/offline: %s", exc)
        return [], True


async def screen_live_adverse_media(
    subject_name: str,
    country: Optional[str] = None,
    entity_type: Optional[str] = None,
    max_articles: int = 8,
    articles_override: Optional[List[Dict[str, Any]]] = None,
) -> Dict[str, Any]:
    """
    Runs live OSINT adverse media screening with Redis 6h caching, GDELT 2.0 ingestion,
    and sentence-window entity disambiguation.
    """
    clean_name = (subject_name or "").strip()
    if not clean_name:
        return {
            "subject_name": "",
            "source": "GDELT_OSINT",
            "total_articles_scanned": 0,
            "adverse_hits": [],
            "highest_risk_score": 0.0,
            "edd_recommended": False,
        }

    country_norm = (country or "").lower()
    raw_cache_str = f"{clean_name.lower()}:{country_norm}"
    cache_hash = hashlib.sha256(raw_cache_str.encode("utf-8")).hexdigest()[:16]

    def _score_articles(articles: list[dict[str, Any]], fetch_had_error: bool) -> dict[str, Any]:
        source_label = (
            "GDELT_2_0_UNAVAILABLE"
            if fetch_had_error
            else ("GDELT_2_0_LIVE" if articles else "GDELT_2_0_LIVE_NO_HITS")
        )
        adverse_hits: List[Dict[str, Any]] = []
        suppressed_count = 0
        highest_risk = 0.0

        for art in articles:
            title = str(art.get("title") or "")
            snippet = str(art.get("snippet") or art.get("seendate") or "")
            combined_text = f"{title}. {snippet}".strip()
            scored = disambiguate_adverse_hit(clean_name, combined_text, country=country, entity_type=entity_type)
            if scored.get("false_positive_suppressed"):
                suppressed_count += 1
            if scored.get("match_found"):
                highest_risk = max(highest_risk, float(scored["risk_score"]))
                adverse_hits.append({
                    "title": title,
                    "url": art.get("url") or "",
                    "domain": art.get("domain") or "",
                    "published_at": art.get("seendate") or art.get("published_at") or "",
                    "matched_categories": scored["matched_categories"],
                    "risk_score": scored["risk_score"],
                    "disambiguation_confidence": scored["disambiguation_confidence"],
                    "same_sentence_match": scored["same_sentence_match"],
                    "excerpt": scored.get("excerpt") or title,
                })

        adverse_hits.sort(key=lambda x: (x["risk_score"], x["disambiguation_confidence"]), reverse=True)
        return {
            "subject_name": clean_name,
            "country": country,
            "source": source_label,
            "screened_at": datetime.now(timezone.utc).isoformat(),
            "total_articles_scanned": len(articles),
            "adverse_hits_count": len(adverse_hits),
            "false_positives_suppressed": suppressed_count,
            "highest_risk_score": round(highest_risk, 2),
            "edd_recommended": highest_risk >= 0.60,
            "adverse_hits": adverse_hits,
        }

    if articles_override is not None:
        return _score_articles(articles_override, False)

    from services.cache_aside import cache_aside

    fallback_holder: dict[str, Any] = {}

    async def _load_live_osint() -> dict[str, Any] | None:
        articles, fetch_had_error = await _fetch_gdelt_articles(clean_name, max_articles)
        res = _score_articles(articles, fetch_had_error)
        # Never cache 6h when live GDELT call errored/timed out
        if fetch_had_error:
            fallback_holder["result"] = res
            return None
        return res

    cached_or_live = await cache_aside.get_or_load(
        namespace="osint_adverse",
        tenant_id="global",
        key=cache_hash,
        loader=_load_live_osint,
        base_ttl=OSINT_CACHE_TTL_SECONDS,
        cache_none=False,
    )
    if cached_or_live is None and "result" in fallback_holder:
        return fallback_holder["result"]
    return cached_or_live
