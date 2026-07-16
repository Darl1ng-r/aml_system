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


_HTML_TAG_RE = re.compile(r"<[^>]*?>")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def sanitize_text(val: Any) -> Any:
    """
    Sanitizes string inputs by:
    1. Stripping null bytes and invisible control characters.
    2. Stripping HTML/script tags.
    3. Decoding HTML entities.
    4. Trimming leading/trailing whitespace.
    """
    if not isinstance(val, str):
        return val

    # Remove null bytes and control chars
    cleaned = _CONTROL_CHAR_RE.sub("", val)
    # Remove HTML tags
    cleaned = _HTML_TAG_RE.sub("", cleaned)
    # Decode unescaped HTML entities
    cleaned = html.unescape(cleaned)
    # Trim leading/trailing whitespace
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
