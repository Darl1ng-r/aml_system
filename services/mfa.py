"""
Multi-Factor Authentication (MFA) — RFC 6238 TOTP Engine
=========================================================
Implements RFC 6238 Time-based One-Time Password (TOTP) compatible with:
  - Google Authenticator
  - Microsoft Authenticator
  - 1Password / Bitwarden / Authy
  - YubiKey Authenticator

Includes backup single-use recovery code generation and verification.
"""

import base64
import hashlib
import hmac
import secrets
import struct
import time
import urllib.parse
from typing import List, Tuple


def generate_totp_secret(length: int = 20) -> str:
    """
    Generates a secure cryptographically random Base32 TOTP secret.
    Default 20 bytes (160 bits) yields a 32-character base32 string.
    """
    random_bytes = secrets.token_bytes(length)
    return base64.b32encode(random_bytes).decode("utf-8").replace("=", "")


def get_totp_uri(secret: str, username: str, issuer: str = "AML-Compliance-Portal") -> str:
    """
    Constructs standard otpauth:// URI for authenticator QR codes.
    """
    label = f"{issuer}:{username}"
    params = {
        "secret": secret,
        "issuer": issuer,
        "algorithm": "SHA1",
        "digits": "6",
        "period": "30",
    }
    query_string = urllib.parse.urlencode(params)
    return f"otpauth://totp/{urllib.parse.quote(label)}?{query_string}"


def generate_totp_code(secret: str, for_time: float | None = None, time_step: int = 30, digits: int = 6) -> str:
    """
    Generates a 6-digit TOTP code for a given timestamp according to RFC 6238 & RFC 4226.
    """
    if for_time is None:
        for_time = time.time()

    counter = int(for_time // time_step)
    counter_bytes = struct.pack(">Q", counter)

    # Pad base32 secret if necessary
    padded_secret = secret + "=" * ((8 - len(secret) % 8) % 8)
    key = base64.b32decode(padded_secret, casefold=True)

    # HMAC-SHA1
    hmac_hash = hmac.new(key, counter_bytes, hashlib.sha1).digest()

    # Dynamic truncation (RFC 4226 section 5.4)
    offset = hmac_hash[-1] & 0x0F
    binary = struct.unpack(">I", hmac_hash[offset:offset + 4])[0] & 0x7FFFFFFF
    code = str(binary % (10 ** digits)).zfill(digits)
    return code


def verify_totp_code(secret: str, code: str, window: int = 1, time_step: int = 30) -> bool:
    """
    Validates a 6-digit user-provided TOTP code against the secret.
    Allows clock drift window: window=1 checks [t-30s, t, t+30s].
    Uses constant-time comparison to prevent timing side-channel attacks.
    """
    if not secret or not code:
        return False

    code = str(code).strip()
    if len(code) != 6 or not code.isdigit():
        return False

    current_time = time.time()
    for offset in range(-window, window + 1):
        step_time = current_time + (offset * time_step)
        expected_code = generate_totp_code(secret, for_time=step_time, time_step=time_step)
        if hmac.compare_digest(code, expected_code):
            return True

    return False


def generate_recovery_codes(count: int = 8) -> Tuple[List[str], List[str]]:
    """
    Generates single-use backup recovery codes.
    Returns:
      (plaintext_codes_for_user, hashed_codes_for_database)
    """
    plaintext_codes = []
    hashed_codes = []
    for _ in range(count):
        part1 = secrets.token_hex(3).upper()
        part2 = secrets.token_hex(3).upper()
        code = f"{part1}-{part2}"
        plaintext_codes.append(code)
        
        # Hash with SHA-256 for secure DB storage
        h = hashlib.sha256(code.encode("utf-8")).hexdigest()
        hashed_codes.append(h)

    return plaintext_codes, hashed_codes


def verify_and_consume_recovery_code(entered_code: str, stored_hashes: List[str]) -> Tuple[bool, List[str]]:
    """
    Verifies a backup recovery code.
    If valid, removes the consumed code from the stored list and returns (True, updated_hashes).
    If invalid, returns (False, stored_hashes).
    """
    if not entered_code or not stored_hashes:
        return False, stored_hashes

    normalized = entered_code.strip().upper()
    code_hash = hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    remaining_hashes = []
    found = False
    for h in stored_hashes:
        if hmac.compare_digest(h, code_hash) and not found:
            found = True
            # Skip adding to remaining_hashes -> consumes the single-use code
        else:
            remaining_hashes.append(h)

    return found, remaining_hashes
