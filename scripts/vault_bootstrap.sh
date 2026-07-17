#!/usr/bin/env bash
# =============================================================================
# scripts/vault_bootstrap.sh
# AML Platform — One-shot Vault seeding script
#
# Prerequisites:
#   - vault CLI installed and on PATH
#   - VAULT_ADDR and VAULT_TOKEN environment variables set
#     (or vault server -dev running locally)
#
# Usage:
#   export VAULT_ADDR=http://127.0.0.1:8200
#   export VAULT_TOKEN=root   # dev mode token
#   bash scripts/vault_bootstrap.sh
#
# After running, copy the printed ROLE_ID and SECRET_ID into your .env:
#   VAULT_ROLE_ID=<role_id>
#   VAULT_SECRET_ID=<secret_id>
# =============================================================================
set -euo pipefail

echo "=== AML Platform :: Vault Bootstrap ==="
echo "VAULT_ADDR: ${VAULT_ADDR:?'VAULT_ADDR must be set'}"

# ── 1. Enable KV-v2 secrets engine (idempotent) ──────────────────────────────
echo "[1/6] Enabling KV-v2 secrets engine at 'secret/'..."
vault secrets enable -path=secret kv-v2 2>/dev/null || \
  echo "      (KV-v2 already enabled — skipping)"

# ── 2. Write placeholder secrets ──────────────────────────────────────────────
echo "[2/6] Writing placeholder secrets to KV-v2 paths..."

vault kv put secret/aml/postgres \
  user="postgres" \
  password="CHANGE_ME_POSTGRES_PASSWORD" \
  host="localhost" \
  port="5433" \
  db="aml_db"

vault kv put secret/aml/neo4j \
  user="neo4j" \
  password="CHANGE_ME_NEO4J_PASSWORD" \
  uri="bolt://localhost:7687"

vault kv put secret/aml/elasticsearch \
  user="elastic" \
  password="CHANGE_ME_ELASTIC_PASSWORD"

vault kv put secret/aml/jwt \
  secret_keys="CHANGE_ME_JWT_KEY_PRIMARY,CHANGE_ME_JWT_KEY_OLD"

vault kv put secret/aml/fincen \
  api_key="CHANGE_ME_FINCEN_API_KEY" \
  file_password="CHANGE_ME_FINCEN_FILE_PASSWORD" \
  transmitter_tin="CHANGE_ME_TRANSMITTER_TIN" \
  efiling_url="https://bsaefiling.fincen.treas.gov/api/v2/sar/submit"

vault kv put secret/aml/watchlists \
  worldcheck_api_key="CHANGE_ME_WORLDCHECK_KEY" \
  worldcheck_api_secret="CHANGE_ME_WORLDCHECK_SECRET" \
  dowjones_api_key="CHANGE_ME_DOWJONES_KEY"

vault kv put secret/aml/supabase \
  url="https://your-project.supabase.co" \
  key="CHANGE_ME_SUPABASE_ANON_KEY"

echo "      Secrets written."

# ── 3. Write and apply the ACL policy ─────────────────────────────────────────
echo "[3/6] Writing AML platform policy..."
vault policy write aml-platform scripts/vault_policy.hcl

# ── 4. Enable AppRole auth (idempotent) ───────────────────────────────────────
echo "[4/6] Enabling AppRole auth method..."
vault auth enable approle 2>/dev/null || \
  echo "      (AppRole already enabled — skipping)"

# ── 5. Create the AppRole ─────────────────────────────────────────────────────
echo "[5/6] Creating 'aml-platform' AppRole..."
vault write auth/approle/role/aml-platform \
  token_policies="aml-platform" \
  token_ttl="1h" \
  token_max_ttl="4h" \
  secret_id_ttl="0"     # non-expiring secret_id; rotate manually on compromise

# ── 6. Print credentials ──────────────────────────────────────────────────────
echo "[6/6] Fetching AppRole credentials..."
ROLE_ID=$(vault read -field=role_id auth/approle/role/aml-platform/role-id)
SECRET_ID=$(vault write -force -field=secret_id auth/approle/role/aml-platform/secret-id)

echo ""
echo "=== Bootstrap Complete ==="
echo ""
echo "Add the following to your production .env or secrets manager:"
echo ""
echo "  VAULT_ADDR=${VAULT_ADDR}"
echo "  VAULT_ROLE_ID=${ROLE_ID}"
echo "  VAULT_SECRET_ID=${SECRET_ID}"
echo ""
echo "IMPORTANT: Replace all CHANGE_ME_* placeholder values with real credentials:"
echo "  vault kv patch secret/aml/postgres password='<real_password>'"
echo "  vault kv patch secret/aml/jwt secret_keys='<real_key>'"
echo "  (repeat for each secret path)"
echo ""
echo "WARNING: The SECRET_ID above is sensitive. Treat it like a password."
