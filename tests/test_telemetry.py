from tls_scanner.models import TLSResult
from tls_scanner.telemetry import record_endpoint


class CapturingSpan:
    def __init__(self):
        self.events = []

    def add_event(self, name, attributes):
        self.events.append((name, attributes))


def test_endpoint_event_contains_certificate_identity_fields():
    span = CapturingSpan()
    result = TLSResult(
        endpoint="example.com",
        subject="commonName=example.com",
        issuer="commonName=Example CA",
    )

    record_endpoint(span, "scan-1", "example.com", "sslyze", "pass", result, "")

    _, attributes = span.events[0]
    assert attributes["tls.certificate.subject"] == "commonName=example.com"
    assert attributes["tls.certificate.issuer"] == "commonName=Example CA"