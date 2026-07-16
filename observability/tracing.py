"""
OpenTelemetry Distributed Tracing
===================================
Initialises a TracerProvider that exports spans to a Jaeger-compatible OTLP
gRPC endpoint.  The ``init_tracer()`` function should be called once at app
startup; ``get_tracer()`` returns a named tracer for manual span creation.

Configuration (via environment / config.py):
  OTEL_SERVICE_NAME           — logical service name (default: aml-platform)
  OTEL_EXPORTER_OTLP_ENDPOINT — Jaeger OTLP gRPC collector (default: http://localhost:4317)
"""

import logging

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource, SERVICE_NAME
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

logger = logging.getLogger(__name__)

_initialised = False


def init_tracer(
    service_name: str = "aml-platform",
    endpoint: str = "http://localhost:4317",
) -> None:
    """
    Bootstrap the global TracerProvider.

    Safe to call multiple times — only the first invocation takes effect.
    """
    global _initialised
    if _initialised:
        return

    resource = Resource.create({SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource)

    exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
    provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    _initialised = True
    logger.info(
        f"OpenTelemetry tracer initialised — exporting to {endpoint} "
        f"as service '{service_name}'"
    )


def get_tracer(name: str = __name__) -> trace.Tracer:
    """Returns a named tracer from the global TracerProvider."""
    return trace.get_tracer(name)
