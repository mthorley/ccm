import pytest
from opentelemetry import trace

from tls_scanner import telemetry
from tls_scanner.config import Config
from tls_scanner.main import run_scan
from tls_scanner.models import Policy, TLSResult


@pytest.fixture(autouse=True)
def no_span_export(monkeypatch):
    """Use a non-recording tracer so nothing is queued for the OTLP exporter."""
    monkeypatch.setattr(telemetry, "tracer", trace.NoOpTracer())


class FakeScanner:
    name = "fake"

    def scan(self, endpoint, timeout_seconds, ca_file=None):
        return TLSResult(endpoint=endpoint, reachable=True, certificate_valid=True, tls_version="TLSv1.3")


def test_run_scan_reports_execution_time():
    config = Config(
        endpoints=["a.example", "b.example"],
        timeout_seconds=1,
        policies=[Policy("valid", "result.certificate_valid", "pass", "CCM-TLS-00")],
    )

    outcome, results, duration_seconds = run_scan(config, FakeScanner())

    assert outcome == "pass"
    assert len(results) == 2
    assert duration_seconds >= 0
    assert all(row["duration_seconds"] >= 0 for row in results)
    assert duration_seconds >= max(row["duration_seconds"] for row in results)
