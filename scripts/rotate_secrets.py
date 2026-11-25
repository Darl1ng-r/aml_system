"""
Secret Rotation Utility CLI Script (RS256 Asymmetric Keypair Rotation)
======================================================================
Generates a fresh 2048-bit RSA private keypair and writes it safely to a 0600
output file (never echoing private key material or active secrets to stdout).

Usage:
  python scripts/rotate_secrets.py --generate-rsa-key --out /tmp/jwt_private.pem
  python scripts/rotate_secrets.py --list-kids
"""

import argparse
import hashlib
import os
import stat
import sys

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.secrets_manager import get_jwks


def generate_rsa_keypair_to_file(out_path: str) -> str:
    """Generates an RSA-2048 private key and writes it with 0600 permissions; returns new kid."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    priv_pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    pub_pem = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    kid = "aml-rsa-" + hashlib.sha256(pub_pem).hexdigest()[:12]

    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    fd = os.open(out_path, flags, stat.S_IRUSR | stat.S_IWUSR)
    with os.fdopen(fd, "wb") as f:
        f.write(priv_pem)

    pub_path = f"{out_path}.pub"
    fd_pub = os.open(pub_path, flags, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)
    with os.fdopen(fd_pub, "wb") as f:
        f.write(pub_pem)

    return kid


def main() -> None:
    parser = argparse.ArgumentParser(description="AML Platform RS256 Secret Rotation Tool")
    parser.add_argument(
        "--generate-rsa-key",
        action="store_true",
        help="Generate a new 2048-bit RSA keypair to --out (mode 0600) without printing key material",
    )
    parser.add_argument(
        "--out",
        type=str,
        default="/tmp/jwt_private.pem",
        help="Output path for generated RSA private key PEM",
    )
    parser.add_argument(
        "--list-kids",
        action="store_true",
        help="List currently published JWKS key IDs (public metadata only)",
    )
    args = parser.parse_args()

    if args.generate_rsa_key:
        kid = generate_rsa_keypair_to_file(args.out)
        print(f"Generated RS256 keypair (kid={kid}) at {args.out} (mode 0600) and {args.out}.pub.")
        print("Zero-downtime Vault rotation procedure:")
        print("  1. Save current public key into Vault secret/aml/jwt previous_public_keys.")
        print(f"  2. Write {args.out} into Vault secret/aml/jwt rsa_private_key.")
        print("  3. Wait for access+refresh TTL grace window, then clear previous_public_keys.")
        print(f"  4. Securely delete local file {args.out}.")
        return

    jwks = get_jwks()
    print(f"Published JWKS keys ({len(jwks.get('keys', []))}):")
    for idx, jwk in enumerate(jwks.get("keys", [])):
        role = "PRIMARY" if idx == 0 else "GRACE_PREVIOUS"
        print(f"  [{idx + 1}] ({role}) alg={jwk.get('alg')} kid={jwk.get('kid')}")


if __name__ == "__main__":
    main()
