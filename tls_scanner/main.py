from __future__ import annotations

import argparse
import json
import sys
import time

from .config import load_config
from .models import aggregate_outcomes
from .metrics import record_result, record_scan
from .policy import PolicyEngine
from .scanners import ScannerBackend, scanner_from_environment
from .telemetry import record_endpoint, scan_telemetry, shutdown_telemetry


def run_scan(config, scanner: ScannerBackend | None = None):
    scanner = scanner or scanner_from_environment()
    engine = PolicyEngine(config.policies)
    evaluated = []
    output = []
    with scan_telemetry(scanner.name, len(config.endpoints)) as (span, run_id):
        scan_started = time.monotonic()
        for endpoint in config.endpoints:
            started = time.monotonic()
            result = scanner.scan(endpoint, timeout_seconds=config.timeout_seconds, ca_file=config.ca_file)
            item = engine.evaluate(result)
            evaluated.append(item)
            duration_seconds = time.monotonic() - started
            record_result(endpoint, item.outcome, duration_seconds, result)
            record_endpoint(span, run_id, endpoint, scanner.name, item.outcome, result, item.matched_policy_id, duration_seconds)
            output.append({
                "scan_id": run_id,
                "scanner": scanner.name,
                "endpoint": endpoint,
                "outcome": item.outcome,
                "matched_policy": item.matched_policy,
                "matched_policy_id": item.matched_policy_id,
                "duration_seconds": round(duration_seconds, 3),
                "result": result.to_cel(),
            })
        outcome = aggregate_outcomes(evaluated)
        scan_duration_seconds = round(time.monotonic() - scan_started, 3)
        span.set_attribute("tls.scan.outcome", outcome)
        span.set_attribute("tls.scan.duration_seconds", scan_duration_seconds)
        record_scan(outcome)
    return outcome, output, scan_duration_seconds


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify TLS endpoints with CEL policies")
    parser.add_argument("--config", help="legacy combined YAML/JSON configuration")
    parser.add_argument("--endpoints-config", default="/etc/tls-checker/endpoints.yaml")
    parser.add_argument("--policies-config", default="/etc/tls-checker/policies.yaml")
    args = parser.parse_args()

    try:
        config = load_config(args.config) if args.config else load_config(args.endpoints_config, args.policies_config)
        outcome, results, _ = run_scan(config)
        for result in results:
            print(json.dumps(result, sort_keys=True), flush=True)
        return 1 if outcome == "fail" else 0
    finally:
        shutdown_telemetry()


if __name__ == "__main__":
    sys.exit(main())
