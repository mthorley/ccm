from __future__ import annotations

import time

from prometheus_client import Counter, Gauge, Histogram


endpoint_checks_total = Counter(
    "tls_scanner_endpoint_checks_total",
    "Completed TLS endpoint checks by policy outcome.",
    ("endpoint", "outcome"),
)
endpoint_check_duration_seconds = Histogram(
    "tls_scanner_endpoint_check_duration_seconds",
    "TLS endpoint check duration in seconds.",
    ("endpoint",),
)
endpoint_reachable = Gauge(
    "tls_scanner_endpoint_reachable",
    "Whether the endpoint was reachable during the last check.",
    ("endpoint",),
)
endpoint_certificate_valid = Gauge(
    "tls_scanner_endpoint_certificate_valid",
    "Whether the endpoint certificate was trusted during the last check.",
    ("endpoint",),
)
endpoint_hostname_verified = Gauge(
    "tls_scanner_endpoint_hostname_verified",
    "Whether the endpoint hostname matched the certificate during the last check.",
    ("endpoint",),
)
endpoint_certificate_expiry_timestamp_seconds = Gauge(
    "tls_scanner_endpoint_certificate_expiry_timestamp_seconds",
    "Endpoint certificate expiry as a Unix timestamp.",
    ("endpoint",),
)
endpoint_tls_version_info = Gauge(
    "tls_scanner_endpoint_tls_version_info",
    "TLS version negotiated by the endpoint; value is always 1.",
    ("endpoint", "tls_version"),
)
endpoint_failures_total = Counter(
    "tls_scanner_endpoint_failures_total",
    "Endpoint failures by normalized error category.",
    ("endpoint", "error_category"),
)
scan_total = Counter(
    "tls_scanner_scans_total",
    "Completed configured scans by aggregate outcome.",
    ("outcome",),
)


def record_result(endpoint: str, outcome: str, duration_seconds: float, result: object) -> None:
    endpoint_checks_total.labels(endpoint, outcome).inc()
    endpoint_check_duration_seconds.labels(endpoint).observe(duration_seconds)
    endpoint_reachable.labels(endpoint).set(int(result.reachable))
    endpoint_certificate_valid.labels(endpoint).set(int(result.certificate_valid))
    endpoint_hostname_verified.labels(endpoint).set(int(result.hostname_verified))
    if result.expires_at:
        endpoint_certificate_expiry_timestamp_seconds.labels(endpoint).set(
            result.expires_in_seconds + time.time()
        )
    if result.tls_version:
        endpoint_tls_version_info.labels(endpoint, result.tls_version).set(1)
    if result.error_category:
        endpoint_failures_total.labels(endpoint, result.error_category).inc()


def record_scan(outcome: str) -> None:
    scan_total.labels(outcome).inc()
