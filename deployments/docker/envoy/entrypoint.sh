#!/bin/sh
set -eu

if [ -z "${INTERNAL_GATEWAY_SECRET:-}" ]; then
  echo "CRITICAL: INTERNAL_GATEWAY_SECRET must be set for Envoy gateway." >&2
  exit 1
fi

# Safely render ${INTERNAL_GATEWAY_SECRET} into runtime config (Envoy static YAML does not expand env vars)
sed "s|\${INTERNAL_GATEWAY_SECRET}|${INTERNAL_GATEWAY_SECRET}|g" /etc/envoy/envoy.yaml.tmpl > /tmp/envoy.yaml
exec /usr/local/bin/envoy -c /tmp/envoy.yaml --service-cluster aml-gateway --service-node gateway-0
