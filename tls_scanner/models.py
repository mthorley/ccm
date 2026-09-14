from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class TLSResult:
    endpoint: str
    port: int = 443
    reachable: bool = False
    certificate_valid: bool = False
    hostname_verified: bool = False
    tls_version: str = ""
    cipher: str = ""
    subject: str = ""
    issuer: str = ""
    sans: list[str] = field(default_factory=list)
    expires_at: str = ""
    expires_in_seconds: int = -1
    error_category: str = ""
    error: str = ""

    def to_cel(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Policy:
    name: str
    expression: str
    outcome: str
    id: str = ""


@dataclass
class EvaluatedResult:
    result: TLSResult
    outcome: str
    matched_policy: str = ""
    matched_policy_id: str = ""


OUTCOMES = {"pass", "warn", "fail"}


def aggregate_outcomes(results: list[EvaluatedResult]) -> str:
    outcomes = {item.outcome for item in results}
    if "fail" in outcomes:
        return "fail"
    if "warn" in outcomes:
        return "warn"
    return "pass"
