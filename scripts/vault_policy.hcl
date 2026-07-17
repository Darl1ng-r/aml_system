# vault_policy.hcl
# AML Platform — read-only policy for KV-v2 secret paths
#
# Apply with:
#   vault policy write aml-platform scripts/vault_policy.hcl
#
# This policy grants the minimum required access:
#   - READ  access to all secret paths under secret/data/aml/
#   - LIST  access to enumerate paths under secret/metadata/aml/
#   - No write, delete, or wildcard access anywhere.

path "secret/data/aml/*" {
  capabilities = ["read"]
}

path "secret/metadata/aml/*" {
  capabilities = ["list"]
}
