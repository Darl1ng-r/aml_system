"""
Adverse Media Screening Service (GAP-5)
=======================================
Performs contextual negative news / adverse media screening against financial crime,
corruption, terrorism financing, and fraud taxonomies.
"""

import re
from typing import Dict, Any, List

ADVERSE_TAXONOMIES = {
    "FINANCIAL_CRIME": ["money laundering", "fraud", "embezzlement", "tax evasion", "ponzi"],
    "CORRUPTION": ["bribery", "kickback", "corrupt", "extortion"],
    "TERRORISM": ["terrorist", "sanctions violation", "smuggling", "arms trafficking"],
    "NARCOTICS": ["drug cartel", "narcotics trafficking", "contraband"]
}


def evaluate_adverse_media_text(subject_name: str, article_text: str) -> Dict[str, Any]:
    """
    Evaluates an article snippet for co-occurrence of subject name and adverse risk taxonomies.
    """
    if not subject_name or not article_text:
        return {"match_found": False, "matched_categories": [], "risk_score": 0.0}

    name_tokens = subject_name.lower().split()
    text_lower = article_text.lower()

    # Verify subject name is mentioned
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
        "edd_recommended": risk_score >= 0.60
    }
