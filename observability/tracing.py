"""
OpenTelemetry Distributed Tracing
===================================
Initialises a TracerProvider with ParentBased(TraceIdRatioBased) sampling
and TLS-aware OTLP gRPC export (fixes P0-03 & §4.4).
"""

import logging
import os

from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.sdk.trace.sampling import ParentBased, TraceIdRatioBased

from config import settings

logger = logging.getLogger(__name__)

_initialised = False


def _build_otlp_exporter(endpoint: str) -> OTLPSpanExporter:
    use_tls = bool(getattr(settings, "enable_tls", False)) or endpoint.lower().startswith("https://")
    if not use_tls:
        return OTLPSpanExporter(endpoint=endpoint, insecure=True, timeout=10)

    credentials = None
    try:
        import grpc
        from services.tls_manager import get_tls_cert_paths

        ca_path, cert_path, key_path = get_tls_cert_paths()
        root_certs = open(ca_path, "rb").read() if os.path.exists(ca_path) else None
        cert_chain = open(cert_path, "rb").read() if os.path.exists(cert_path) else None
        priv_key = open(key_path, "rb").read() if os.path.exists(key_path) else None
        credentials = grpc.ssl_channel_credentials(
            root_certificates=root_certs,
            private_key=priv_key,
            certificate_chain=cert_chain,
        )
    except Exception as exc:
        logger.warning("OTLP gRPC mTLS credentials unavailable (%s); falling back to default TLS trust.", exc)

    return OTLPSpanExporter(endpoint=endpoint, insecure=False, credentials=credentials, timeout=10)


def init_tracer(
    service_name: str = "aml-platform",
    endpoint: str = "http://localhost:4317",
) -> None:
    """Bootstrap the global TracerProvider (safe to call multiple times)."""
    global _initialised
    if _initialised:
        return

    sample_rate = max(0.0, min(1.0, float(getattr(settings, "otel_trace_sample_rate", 0.1))))
    sampler = ParentBased(root=TraceIdRatioBased(sample_rate))
    resource = Resource.create({SERVICE_NAME: service_name})
    provider = TracerProvider(resource=resource, sampler=sampler)

    exporter = _build_otlp_exporter(endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))

    trace.set_tracer_provider(provider)
    _initialised = True
    logger.info(
        "OpenTelemetry tracer initialised — exporting to %s as '%s' (tls=%s, sample_rate=%.2f)",
        endpoint,
        service_name,
        bool(getattr(settings, "enable_tls", False)) or endpoint.lower().startswith("https://"),
        sample_rate,
    )


def get_tracer(name: str = __name__) -> trace.Tracer:
    """Returns a named tracer from the global TracerProvider."""
    return trace.get_tracer(name)
