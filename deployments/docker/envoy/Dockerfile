FROM envoyproxy/envoy:v1.28.7
COPY envoy.yaml /etc/envoy/envoy.yaml.tmpl
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod 755 /usr/local/bin/entrypoint.sh
USER envoy
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
