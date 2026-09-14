from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from .models import Policy


@dataclass(frozen=True)
class Config:
    endpoints: list[str]
    timeout_seconds: float
    policies: list[Policy]
    ca_file: str | None = None


def _load_document(path: str) -> dict:
    return yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}


def load_config(endpoint_path: str, policy_path: str | None = None) -> Config:
    endpoint_document = _load_document(endpoint_path)
    policy_document = _load_document(policy_path) if policy_path else endpoint_document
    endpoints = endpoint_document.get("endpoints", [])
    if not endpoints or any(not isinstance(endpoint, str) or not endpoint.strip() for endpoint in endpoints):
        raise ValueError("endpoints must be a non-empty list of hostnames")
    policies = [
        Policy(item["name"], item["expression"], item["outcome"], item["id"])
        for item in policy_document.get("policies", [])
    ]
    return Config(
        endpoints=[endpoint.strip().lower().rstrip(".") for endpoint in endpoints],
        timeout_seconds=float(endpoint_document.get("timeout_seconds", 10)),
        policies=policies,
        ca_file=endpoint_document.get("ca_file"),
    )
