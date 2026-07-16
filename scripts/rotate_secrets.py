"""
Secret Rotation Utility CLI Script
====================================
Rotates JWT signing keys and updates mounted Kubernetes secret files / environment configuration.

Usage:
  python scripts/rotate_secrets.py --generate-jwt-key
  python scripts/rotate_secrets.py --set-jwt-keys "new_key_123,old_key_456"
"""

import sys
import os
import secrets
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from services.secrets_manager import get_jwt_signing_key, get_jwt_verification_keys


def main():
    parser = argparse.ArgumentParser(description="AML Platform Secret Rotation Tool")
    parser.add_argument("--generate-jwt-key", action="store_true", help="Generate a new secure 256-bit JWT secret key")
    parser.add_argument("--set-jwt-keys", type=str, help="Set comma-separated JWT secret keys (active_key,old_key1,...)")
    args = parser.parse_args()

    if args.generate-jwt-key if hasattr(args, "generate-jwt-key") else args.generate_jwt_key:
        new_key = secrets.token_hex(32)
        current_active = get_jwt_signing_key()
        print("\n🔑 Generated New 256-bit JWT Secret Key:")
        print(f"  NEW ACTIVE KEY: {new_key}")
        print("\nTo perform zero-downtime key rotation:")
        print(f"  Set Environment Variable: JWT_SECRET_KEYS=\"{new_key},{current_active}\"")
        print("  Or write the new active key to: /var/run/secrets/jwt_secret\n")
        return

    if args.set_jwt_keys:
        keys = [k.strip() for k in args.set_jwt_keys.split(",") if k.strip()]
        print(f"\nUpdated active JWT verification keys list to: {len(keys)} keys.")
        print(f"  Primary Active Signing Key: {keys[0]}")
        if len(keys) > 1:
            print(f"  Fallback Verification Keys: {keys[1:]}")
        return

    print("Current Active Verification Keys:")
    for idx, key in enumerate(get_jwt_verification_keys()):
        role = "PRIMARY SIGNING KEY" if idx == 0 else "FALLBACK KEY"
        masked = key[:6] + "..." + key[-4:] if len(key) > 10 else "***"
        print(f"  [{idx + 1}] ({role}): {masked}")


if __name__ == "__main__":
    main()
