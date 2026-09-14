"""
Test Suite: OpenTelemetry Distributed Tracing & Compliance Telemetry (Finding #33)
==================================================================================
Validates that OpenTelemetry spans, attributes, events, and W3C trace-context
propagation function accurately for compliance auditability.
"""

from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import SimpleSpanProcessor
from opentelemetry.sdk.trace.export.in_memory_span_exporter import InMemorySpanExporter
from opentelemetry.sdk.resources import Resource
from opentelemetry.trace.status import StatusCode, Status
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry import context as otel_context


def test_opentelemetry_span_creation_and_attributes():
    """
    Verify that custom AML transaction and alert scoring spans are emitted
    with necessary compliance attributes, tenant context, and events.
    """
    exporter = InMemorySpanExporter()
    resource = Resource.create({"service.name": "aml-platform-test"})
    provider = TracerProvider(resource=resource)
    provider.add_span_processor(SimpleSpanProcessor(exporter))

    tracer = provider.get_tracer("aml.compliance.scoring")

    tenant_id = "11111111-2222-3333-4444-555555555555"
    tx_id = "tx-9999-compliance"

    with tracer.start_as_current_span("aml.transaction.score") as span:
        span.set_attribute("tenant.id", tenant_id)
        span.set_attribute("transaction.id", tx_id)
        span.set_attribute("aml.risk.score", 0.92)
        span.set_attribute("aml.rule.triggered", "R_STRUCTURING_HIGH")
        span.add_event(
            "rule_evaluation_complete",
            attributes={"rules_evaluated": 12, "execution_ms": 1.4}
        )
        span.set_status(Status(StatusCode.OK))

    # Retrieve emitted spans from in-memory collector
    spans = exporter.get_finished_spans()
    assert len(spans) == 1

    finished_span = spans[0]
    assert finished_span.name == "aml.transaction.score"
    assert finished_span.status.status_code == StatusCode.OK

    attrs = finished_span.attributes
    assert attrs["tenant.id"] == tenant_id
    assert attrs["transaction.id"] == tx_id
    assert attrs["aml.risk.score"] == 0.92
    assert attrs["aml.rule.triggered"] == "R_STRUCTURING_HIGH"

    # Verify event capture
    assert len(finished_span.events) == 1
    event = finished_span.events[0]
    assert event.name == "rule_evaluation_complete"
    assert event.attributes["rules_evaluated"] == 12

    # Verify valid RFC 0000 trace and span identifiers
    ctx = finished_span.get_span_context()
    assert ctx.trace_id > 0
    assert ctx.span_id > 0


def test_trace_context_propagation_w3c():
    """
    Verify W3C traceparent context injection and extraction across async worker boundaries.
    """
    exporter = InMemorySpanExporter()
    provider = TracerProvider()
    provider.add_span_processor(SimpleSpanProcessor(exporter))
    tracer = provider.get_tracer("aml.messaging")

    propagator = TraceContextTextMapPropagator()
    carrier = {}

    with tracer.start_as_current_span("producer.publish_transaction") as producer_span:
        propagator.inject(carrier)
        assert "traceparent" in carrier

        traceparent = carrier["traceparent"]
        producer_ctx = producer_span.get_span_context()
        trace_id_hex = format(producer_ctx.trace_id, "032x")
        assert trace_id_hex in traceparent

    # Simulate consumer extracting traceparent on the other end of Redpanda / Kafka
    extracted_context = propagator.extract(carrier)
    token = otel_context.attach(extracted_context)
    try:
        with tracer.start_as_current_span("consumer.process_transaction") as consumer_span:
            consumer_ctx = consumer_span.get_span_context()
            # Child span in consumer must share the exact same root trace_id
            assert consumer_ctx.trace_id == producer_ctx.trace_id
            assert consumer_ctx.span_id != producer_ctx.span_id
    finally:
        otel_context.detach(token)

    finished = exporter.get_finished_spans()
    assert len(finished) == 2
