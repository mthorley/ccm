from tls_scanner.config import load_config


def test_loads_split_endpoint_and_policy_files(tmp_path):
    endpoints = tmp_path / "endpoints.yaml"
    endpoints.write_text(
        "endpoints:\n  - Example.COM.\ntimeout_seconds: 3\n",
        encoding="utf-8",
    )
    policies = tmp_path / "policies.yaml"
    policies.write_text(
        "policies:\n  - id: CCM-TLS-01\n    name: tls-validity\n    expression: result.reachable\n    outcome: fail\n",
        encoding="utf-8",
    )

    config = load_config(str(endpoints), str(policies))

    assert config.endpoints == ["example.com"]
    assert config.timeout_seconds == 3
    assert config.policies[0].id == "CCM-TLS-01"
