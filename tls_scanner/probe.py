from __future__ import annotations

import datetime as dt
import traceback

from cryptography.x509 import DNSName, ExtensionNotFound, ExtensionOID
from sslyze.plugins.scan_commands import ScanCommand
from sslyze.scanner.models import ServerScanRequest
from sslyze.scanner.scanner import Scanner
from sslyze.server_setting import ServerNetworkConfiguration, ServerNetworkLocation

from .models import TLSResult


def _certificate_name(name: object) -> str:
    return ", ".join(f"{attribute.oid._name}={attribute.value}" for attribute in name)


def _certificate_sans(certificate: object) -> list[str]:
    try:
        extension = certificate.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        return extension.value.get_values_for_type(DNSName)
    except ExtensionNotFound:
        return []


def _expires_in_seconds(certificate: object) -> tuple[str, int]:
    expires_at = getattr(certificate, "not_valid_after_utc", None) or certificate.not_valid_after
    if expires_at.tzinfo is None:
        expires_at = expires_at.replace(tzinfo=dt.timezone.utc)
    return expires_at.isoformat(), max(0, int((expires_at - dt.datetime.now(dt.timezone.utc)).total_seconds()))


def probe_endpoint(
    endpoint: str,
    *,
    port: int = 443,
    timeout_seconds: float = 10.0,
    minimum_tls: object | None = None,
    ca_file: str | None = None,
) -> TLSResult:
    del minimum_tls, ca_file
    result = TLSResult(endpoint=endpoint, port=port)
    request = ServerScanRequest(
        server_location=ServerNetworkLocation(endpoint, port),
        network_configuration=ServerNetworkConfiguration(
            tls_server_name_indication=endpoint,
            network_timeout=int(timeout_seconds),
            network_max_retries=0,
        ),
        scan_commands={
            ScanCommand.CERTIFICATE_INFO,
            ScanCommand.TLS_1_2_CIPHER_SUITES,
            ScanCommand.TLS_1_3_CIPHER_SUITES,
        },
    )

    try:
        scanner = Scanner(concurrent_server_scans_limit=1)
        scanner.queue_scans([request])
        scan = next(scanner.get_results())
        if scan.connectivity_status.name != "COMPLETED":
            result.error_category = "connection_error"
            result.error = str(scan.connectivity_error_trace or scan.connectivity_status)
            return result

        result.reachable = True
        attempts = scan.scan_result
        certificate_scan = attempts.certificate_info.result
        deployment = certificate_scan.certificate_deployments[0]
        certificate = deployment.received_certificate_chain[0]
        result.certificate_valid = any(
            validation.verified_certificate_chain
            for validation in deployment.path_validation_results
        )
        result.hostname_verified = certificate_scan.hostname_used_for_server_name_indication == endpoint
        result.subject = _certificate_name(certificate.subject)
        result.issuer = _certificate_name(certificate.issuer)
        result.sans = _certificate_sans(certificate)
        result.expires_at, result.expires_in_seconds = _expires_in_seconds(certificate)

        tls13 = attempts.tls_1_3_cipher_suites.result
        tls12 = attempts.tls_1_2_cipher_suites.result
        if tls13 and tls13.accepted_cipher_suites:
            result.tls_version = "TLSv1.3"
            result.cipher = tls13.accepted_cipher_suites[0].cipher_suite.name
        elif tls12 and tls12.accepted_cipher_suites:
            result.tls_version = "TLSv1.2"
            result.cipher = tls12.accepted_cipher_suites[0].cipher_suite.name
        else:
            result.error_category = "tls_error"
            result.error = "no TLS 1.2 or TLS 1.3 cipher suite accepted"
    except TimeoutError as exc:
        result.error_category = "timeout"
        result.error = str(exc) or "connection timed out"
    except Exception as exc:
        result.error_category = "tls_error"
        result.error = "".join(traceback.format_exception_only(type(exc), exc)).strip()
    return result
