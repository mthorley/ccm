from __future__ import annotations

import json
import os
import urllib.request
from dataclasses import dataclass
from typing import Protocol

from .models import TLSResult
class ScannerBackend(Protocol):
    name: str

    def scan(self, endpoint: str, timeout_seconds: float, ca_file: str | None = None) -> TLSResult:
        ...


@dataclass(frozen=True)
class SslYzeScanner:
    name: str = "sslyze"

    def scan(self, endpoint: str, timeout_seconds: float, ca_file: str | None = None) -> TLSResult:
        from .probe import probe_endpoint

        return probe_endpoint(endpoint, timeout_seconds=timeout_seconds, ca_file=ca_file)


@dataclass(frozen=True)
class WizScanner:
    """Adapter for a Wiz scanning service that returns a normalized TLSResult JSON object.

    The service receives {"endpoint": "host"} and must return the TLSResult fields.
    Authentication is supplied with WIZ_SCANNER_TOKEN and never emitted as telemetry.
    """

    base_url: str
    token: str | None = None
    name: str = "wiz"

    def scan(self, endpoint: str, timeout_seconds: float, ca_file: str | None = None) -> TLSResult:
        del ca_file
        payload = json.dumps({"endpoint": endpoint}).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(
            f"{self.base_url.rstrip('/')}/scan",
            data=payload,
            headers=headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout_seconds) as response:
                document = json.loads(response.read().decode("utf-8"))
            result = document.get("result", document)
            return TLSResult(endpoint=endpoint, **{key: result[key] for key in TLS_RESULT_FIELDS if key in result})
        except TimeoutError as exc:
            return TLSResult(endpoint=endpoint, error_category="timeout", error=str(exc) or "Wiz scanner timed out")
        except Exception as exc:
            return TLSResult(endpoint=endpoint, error_category="scanner_error", error=str(exc))


TLS_RESULT_FIELDS = {
    "port",
    "reachable",
    "certificate_valid",
    "hostname_verified",
    "tls_version",
    "cipher",
    "subject",
    "issuer",
    "sans",
    "expires_at",
    "expires_in_seconds",
    "error_category",
    "error",
}


def scanner_from_environment() -> ScannerBackend:
    backend = os.getenv("TLS_SCANNER_BACKEND", "sslyze").lower()
    if backend == "sslyze":
        return SslYzeScanner()
    if backend == "wiz":
        base_url = os.getenv("WIZ_SCANNER_URL")
        if not base_url:
            raise ValueError("WIZ_SCANNER_URL is required when TLS_SCANNER_BACKEND=wiz")
        return WizScanner(base_url=base_url, token=os.getenv("WIZ_SCANNER_TOKEN"))
    raise ValueError(f"unsupported scanner backend: {backend}")
