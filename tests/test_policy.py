import pytest

from tls_scanner.models import Policy, TLSResult, aggregate_outcomes
from tls_scanner.policy import PolicyEngine


def test_policy_matches_expired_certificate():
    engine = PolicyEngine([
        Policy("expired", "!result.certificate_valid", "fail", "CCM-TLS-01"),
        Policy("expiring-soon", "result.expires_in_seconds < 604800", "warn", "CCM-TLS-02"),
    ])

    evaluated = engine.evaluate(TLSResult(endpoint="expired.example", certificate_valid=False))

    assert evaluated.outcome == "fail"
    assert evaluated.matched_policy == "expired"
    assert evaluated.matched_policy_id == "CCM-TLS-01"


def test_policy_can_check_tls_version_and_expiry():
    engine = PolicyEngine([
        Policy("old-tls", "result.tls_version != 'TLSv1.3'", "warn"),
    ])

    evaluated = engine.evaluate(
        TLSResult(endpoint="example.com", certificate_valid=True, tls_version="TLSv1.2")
    )

    assert evaluated.outcome == "warn"


def test_cipher_suite_policy_accepts_compliant_tls12_and_rejects_other_ciphers():
    expression = (
        "!(result.tls_version == 'TLSv1.2' && "
        "(result.cipher == 'ECDHE-RSA-AES128-GCM-SHA256' || "
        "result.cipher == 'ECDHE-RSA-AES256-GCM-SHA384')) && "
        "!(result.tls_version == 'TLSv1.3' && "
        "(result.cipher == 'TLS_AES_128_GCM_SHA256' || "
        "result.cipher == 'TLS_AES_256_GCM_SHA384'))"
    )
    engine = PolicyEngine([Policy("cipher-suite-compliance", expression, "fail", "CCM-TLS-04")])

    compliant = engine.evaluate(
        TLSResult(endpoint="example.com", tls_version="TLSv1.2", cipher="ECDHE-RSA-AES128-GCM-SHA256")
    )
    non_compliant = engine.evaluate(
        TLSResult(endpoint="example.com", tls_version="TLSv1.2", cipher="AES128-SHA")
    )

    assert compliant.outcome == "pass"
    assert non_compliant.outcome == "fail"
    assert non_compliant.matched_policy_id == "CCM-TLS-04"


def test_unmatched_result_passes():
    engine = PolicyEngine([Policy("bad", "!result.reachable", "fail")])

    evaluated = engine.evaluate(TLSResult(endpoint="example.com", reachable=True))

    assert evaluated.outcome == "pass"
    assert aggregate_outcomes([evaluated]) == "pass"


def test_invalid_outcome_is_rejected():
    with pytest.raises(ValueError, match="unsupported policy outcome"):
        PolicyEngine([Policy("bad", "true", "unknown")])
