from __future__ import annotations

import os
import uuid
from contextlib import contextmanager
from typing import Iterator

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter


_provider = TracerProvider(
    resource=Resource.create({
        "service.name": os.getenv("OTEL_SERVICE_NAME", "tls-scanner"),
        "service.version": "0.1.0",
    })
)
_provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
trace.set_tracer_provider(_provider)
tracer = trace.get_tracer("tls-scanner")


def shutdown_telemetry() -> None:
    """Flush buffered spans before a short-lived process exits."""
    _provider.force_flush(timeout_millis=10_000)
    _provider.shutdown()


@contextmanager
def scan_telemetry(scanner_name: str, endpoint_count: int) -> Iterator[tuple[object, str]]:
    run_id = str(uuid.uuid4())
    with tracer.start_as_current_span("tls.scan", attributes={
        "tls.scan.id": run_id,
        "tls.scanner.name": scanner_name,
        "tls.endpoint.count": endpoint_count,
    }) as span:
        yield span, run_id


def record_endpoint(
    span: object,
    run_id: str,
    endpoint: str,
    scanner_name: str,
    outcome: str,
    result: object,
    policy_id: str,
    duration_seconds: float = 0.0,
) -> None:
    span.add_event("tls.endpoint.result", {
        "tls.scan.id": run_id,
        "tls.endpoint": endpoint,
        "tls.scanner.name": scanner_name,
        "tls.outcome": outcome,
        "tls.policy.id": policy_id,
        "tls.check.duration_seconds": round(duration_seconds, 3),
        "tls.reachable": result.reachable,
        "tls.certificate.valid": result.certificate_valid,
        "tls.hostname.verified": result.hostname_verified,
        "tls.version": result.tls_version,
        "tls.cipher": result.cipher,
        "tls.certificate.subject": result.subject,
        "tls.certificate.issuer": result.issuer,
        "tls.certificate.expires_at": result.expires_at,
        "tls.error.category": result.error_category,
    })
