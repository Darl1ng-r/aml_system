FROM envoyproxy/envoy:v1.28-latest
COPY envoy.yaml /etc/envoy/envoy.yaml
USER envoy
CMD ["/usr/local/bin/envoy", "-c", "/etc/envoy/envoy.yaml", "--service-cluster", "aml-gateway", "--service-node", "gateway-0"]
