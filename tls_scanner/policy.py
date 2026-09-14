from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from celpy import Environment
from celpy.adapter import json_to_cel

from .models import EvaluatedResult, OUTCOMES, Policy, TLSResult


@dataclass
class CompiledPolicy:
    policy: Policy
    program: Any


class PolicyEngine:
    def __init__(self, policies: list[Policy]) -> None:
        self._policies = [self._compile(policy) for policy in policies]

    @staticmethod
    def _compile(policy: Policy) -> CompiledPolicy:
        if policy.outcome not in OUTCOMES:
            raise ValueError(f"unsupported policy outcome: {policy.outcome}")
        environment = Environment()
        ast = environment.compile(policy.expression)
        program = environment.program(ast)
        return CompiledPolicy(policy, program)

    def evaluate(self, result: TLSResult) -> EvaluatedResult:
        activation = {"result": json_to_cel(result.to_cel())}
        for compiled in self._policies:
            try:
                matched = compiled.program.evaluate(activation)
            except Exception as exc:
                raise ValueError(f"policy {compiled.policy.name!r} evaluation failed: {exc}") from exc
            if bool(matched):
                return EvaluatedResult(
                    result,
                    compiled.policy.outcome,
                    compiled.policy.name,
                    compiled.policy.id,
                )
        return EvaluatedResult(result, "pass")
