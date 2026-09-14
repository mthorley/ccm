import gzip

from opentelemetry.proto.trace.v1.trace_pb2 import Span

from tls_graph_adapter.main import decode_otlp_body, run_from_span


def test_otlp_body_is_gunzipped_when_declared():
    body = b"otlp-payload"

    assert decode_otlp_body(gzip.compress(body), "gzip") == body


def test_otlp_body_accepts_comma_separated_encodings():
    body = b"otlp-payload"

    assert decode_otlp_body(gzip.compress(body), "identity, gzip") == body


def test_uncompressed_otlp_body_is_unchanged():
    body = b"otlp-payload"

    assert decode_otlp_body(body, None) == body


def _scan_span(**attributes) -> Span:
    span = Span(name="tls.scan", start_time_unix_nano=1_700_000_000_000_000_000, end_time_unix_nano=1_700_000_002_500_000_000)
    for key, value in attributes.items():
        attribute = span.attributes.add()
        attribute.key = key
        if isinstance(value, str):
            attribute.value.string_value = value
        elif isinstance(value, int):
            attribute.value.int_value = value
        else:
            attribute.value.double_value = value
    return span


def test_run_from_span_reads_execution_time_and_identity():
    span = _scan_span(**{
        "tls.scan.id": "scan-1",
        "tls.scanner.name": "sslyze",
        "tls.scan.outcome": "warn",
        "tls.endpoint.count": 3,
        "tls.scan.duration_seconds": 2.468,
    })

    assert run_from_span(span) == {
        "scan_id": "scan-1",
        "scanner": "sslyze",
        "outcome": "warn",
        "endpoint_count": 3,
        "duration_seconds": 2.468,
        "started_at_ms": 1_700_000_000_000,
        "finished_at_ms": 1_700_000_002_500,
    }


def test_run_from_span_falls_back_to_span_timestamps_for_duration():
    run = run_from_span(_scan_span(**{"tls.scan.id": "scan-2"}))

    assert run["duration_seconds"] == 2.5


def test_run_from_span_ignores_spans_without_scan_id():
    assert run_from_span(_scan_span(**{"tls.scanner.name": "sslyze"})) is None
