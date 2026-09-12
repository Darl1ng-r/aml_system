"""
Input Sanitization & Security Validation Utility
=================================================
Provides text sanitization and security constraints for input fields:
  - HTML / Script Tag Stripping: Prevents XSS and HTML injection.
  - Null Byte & Control Character Removal: Prevents control character injection.
  - Automatic Pydantic Field Sanitization: Trims whitespace and strips dangerous characters.
"""

import re
import html
from typing import Any


_HTML_TAG_RE = re.compile(r"<[^<>]*?>")
# Control characters, ASCII unprintable, and Trojan Source bidirectional override / zero-width characters
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]")


def sanitize_text(val: Any) -> Any:
    """
    Sanitizes string inputs by:
    1. Stripping null bytes, control characters, zero-width, and Trojan Source bidi overrides.
    2. Decoding HTML entities to catch obfuscated tags (e.g. &lt;script&gt;).
    3. Iteratively stripping HTML/script tags (preventing nested bypasses like <<script>script>).
    4. Removing lingering angle brackets.
    5. Trimming leading/trailing whitespace.
    """
    if not isinstance(val, str):
        return val

    # 1. Remove null bytes, control chars, and bidi override characters
    cleaned = _CONTROL_CHAR_RE.sub("", val)
    # 2. Decode HTML entities to catch obfuscated tags (e.g. &lt;script&gt;)
    cleaned = html.unescape(cleaned)
    # 3. Iteratively strip HTML/script tags to prevent nested tag injection
    prev = None
    iteration = 0
    while prev != cleaned and iteration < 5:
        prev = cleaned
        cleaned = _HTML_TAG_RE.sub("", cleaned)
        iteration += 1
    # 4. Remove lingering raw bracket characters that could form malformed injection
    cleaned = cleaned.replace("<", "").replace(">", "")
    # 5. Trim leading/trailing whitespace
    return cleaned.strip()


def sanitize_model_dict(data: dict) -> dict:
    """Recursively sanitizes all string fields in a dictionary."""
    sanitized = {}
    for key, val in data.items():
        if isinstance(val, str):
            sanitized[key] = sanitize_text(val)
        elif isinstance(val, dict):
            sanitized[key] = sanitize_model_dict(val)
        elif isinstance(val, list):
            sanitized[key] = [
                sanitize_text(item) if isinstance(item, str)
                else (sanitize_model_dict(item) if isinstance(item, dict) else item)
                for item in val
            ]
        else:
            sanitized[key] = val
    return sanitized
