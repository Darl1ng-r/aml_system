#!/usr/bin/env bash
# =============================================================================
# scripts/vault_bootstrap.sh
# AML Platform — One-shot Vault seeding script (aligned with VAULT_SECRET_PATHS)
# =============================================================================
set -euo pipefail

echo "=== AML Platform :: Vault Bootstrap ==="
echo "VAULT_ADDR: ${VAULT_ADDR:?'VAULT_ADDR must be set'}"

# ── 1. Enable KV-v2 secrets engine (idempotent) ──────────────────────────────
echo "[1/6] Enabling KV-v2 secrets engine at 'secret/'..."
vault secrets enable -path=secret kv-v2 2>/dev/null || \
  echo "      (KV-v2 already enabled — skipping)"

# ── 2. Write placeholder secrets matching canonical VAULT_SECRET_PATHS ────────
echo "[2/6] Writing placeholder secrets to KV-v2 paths under secret/aml/*..."

vault kv put secret/aml/postgres \
  user="aml_app" \
  password="REPLACE_WITH_POSTGRES_ADMIN_PASSWORD" \
  aml_app_password="REPLACE_WITH_AML_APP_PASSWORD" \
  host="aml-pgbouncer-service" \
  port="6432" \
  db="aml_db"

vault kv put secret/aml/redis \
  password="REPLACE_WITH_REDIS_PASSWORD"

vault kv put secret/aml/neo4j \
  user="neo4j" \
  password="REPLACE_WITH_NEO4J_PASSWORD" \
  uri="bolt+s://aml-neo4j-service:7687"

vault kv put secret/aml/elasticsearch \
  user="elastic" \
  password="REPLACE_WITH_ELASTIC_PASSWORD"

vault kv put secret/aml/jwt \
  algorithm="RS256" \
  rsa_private_key="REPLACE_WITH_RSA_2048_PRIVATE_KEY_PEM" \
  previous_public_keys=""

vault kv put secret/aml/encryption \
  pii_key="REPLACE_WITH_HIGH_ENTROPY_PII_KEY"

vault kv put secret/aml/observability \
  metrics_secret="REPLACE_WITH_METRICS_BEARER_TOKEN"

vault kv put secret/aml/gateway \
  internal_secret="REPLACE_WITH_INTERNAL_GATEWAY_SECRET"

vault kv put secret/aml/fincen \
  api_key="REPLACE_WITH_FINCEN_API_KEY" \
  file_password="REPLACE_WITH_FINCEN_FILE_PASSWORD" \
  transmitter_tin="REPLACE_WITH_TRANSMITTER_TIN" \
  efiling_url="https://bsaefiling.fincen.treas.gov/api/v2/sar/submit" \
  sftp_password="REPLACE_WITH_FINCEN_SFTP_PASSWORD"

vault kv put secret/aml/watchlists \
  worldcheck_api_key="REPLACE_WITH_WORLDCHECK_KEY" \
  worldcheck_api_secret="REPLACE_WITH_WORLDCHECK_SECRET" \
  dowjones_api_key="REPLACE_WITH_DOWJONES_KEY"

vault kv put secret/aml/supabase \
  url="https://your-project-ref.supabase.co" \
  key="REPLACE_WITH_SUPABASE_ANON_KEY"

echo "      Secrets written."

# ── 3. Write and apply the ACL policy ─────────────────────────────────────────
echo "[3/6] Writing AML platform policy..."
vault policy write aml-platform scripts/vault_policy.hcl

# ── 4. Enable AppRole auth (idempotent) ───────────────────────────────────────
echo "[4/6] Enabling AppRole auth method..."
vault auth enable approle 2>/dev/null || \
  echo "      (AppRole already enabled — skipping)"

# ── 5. Create the AppRole with finite secret_id_ttl & bounded uses ────────────
echo "[5/6] Creating 'aml-platform' AppRole..."
vault write auth/approle/role/aml-platform \
  token_policies="aml-platform" \
  token_ttl="1h" \
  token_max_ttl="4h" \
  secret_id_ttl="24h" \
  secret_id_num_uses="10"

# ── 6. Write credentials to 0600 file instead of printing secret_id to stdout ─
echo "[6/6] Writing AppRole credentials to secure 0600 file..."
CRED_FILE="${VAULT_BOOTSTRAP_OUT:-/tmp/aml-vault-approle.env}"
umask 077
ROLE_ID=$(vault read -field=role_id auth/approle/role/aml-platform/role-id)
SECRET_ID=$(vault write -force -field=secret_id auth/approle/role/aml-platform/secret-id)
cat > "${CRED_FILE}" <<EOF
VAULT_ADDR=${VAULT_ADDR}
VAULT_ROLE_ID=${ROLE_ID}
VAULT_SECRET_ID=${SECRET_ID}
EOF
chmod 600 "${CRED_FILE}"

echo "=== Bootstrap Complete ==="
echo "AppRole credentials written to ${CRED_FILE} (mode 0600)."
echo "Move into your secret store and shred ${CRED_FILE} immediately."
