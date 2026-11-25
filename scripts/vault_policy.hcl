# vault_policy.hcl
# AML Platform — least-privilege policy for KV-v2 secrets and PKI leaf certs
#
# Apply with:
#   vault policy write aml-platform scripts/vault_policy.hcl

path "secret/data/aml/*" {
  capabilities = ["read"]
}

path "secret/metadata/aml/*" {
  capabilities = ["list"]
}

# Required by Vault Agent Injector in deployments/kubernetes/fastapi-app.yaml
path "pki/issue/aml-cluster-role" {
  capabilities = ["create", "update"]
}
