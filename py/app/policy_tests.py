"""Policy test cases: requests and the outcome policies/aegis.cedar must give them.

The cases live in ``policies/tests.json`` next to the policies, so a change to a guardrail and
the cases that pin its behaviour are reviewed together. They run in CI against the server's
Cedar build and, in the demo smoke test, against Cedar's WebAssembly build.

    python -m app.policy_tests
"""

import json
import sys
from dataclasses import dataclass
from typing import Any

from app.evaluator import NO_JUSTIFICATION, POLICY_DIR, EvaluationResult, evaluate
from app.models import Resource, SensitivityLevel, User
from app.schemas import ParsedPolicy

OUTCOMES = ("allow", "needs-approval", "step-up", "deny")


def outcome(result: EvaluationResult) -> str:
    if result.step_up_required:
        return "step-up"
    if not result.allowed:
        return "deny"
    return "needs-approval" if result.requires_approval else "allow"


@dataclass
class CaseResult:
    name: str
    passed: bool
    expected: str
    actual: str
    because: list[str] | None
    policies: list[str]

    def as_dict(self) -> dict[str, Any]:
        return self.__dict__.copy()


def load_cases() -> list[dict[str, Any]]:
    return json.loads((POLICY_DIR / "tests.json").read_text())["cases"]


def run_case(case: dict[str, Any]) -> CaseResult:
    principal, target, context = case["principal"], case["resource"], case.get("context", {})
    user = User(
        id=1,
        name="test",
        email="test@aegis.example",
        role=principal["role"],
        department=principal.get("department", ""),
        is_active=principal.get("active", True),
    )
    resource = Resource(
        name="test-resource",
        sensitivity_level=SensitivityLevel(target["sensitivity"]),
        owner_department=target.get("owner_department"),
    )
    reason = "Policy test case" if context.get("justification", True) else NO_JUSTIFICATION
    result = evaluate(
        user,
        resource,
        ParsedPolicy(resource=resource.name, action=case["action"], allow_reason=reason, duration_hours=1),
        approved=context.get("approved", False),
        mfa=context.get("mfa", False),
        break_glass=context.get("break_glass", False),
    )
    actual, policies = outcome(result), result.policy_ids
    expected, because = case["expect"], case.get("because")
    passed = actual == expected
    if because is not None:
        exact = expected in ("deny", "step-up")
        passed = passed and (sorted(policies) == sorted(because) if exact else set(because) <= set(policies))
    return CaseResult(case["name"], passed, expected, actual, because, policies)


def run_all() -> list[CaseResult]:
    return [run_case(case) for case in load_cases()]


def main() -> int:
    results = run_all()
    for r in results:
        mark = "ok  " if r.passed else "FAIL"
        detail = "" if r.passed else f"  (expected {r.expected} {r.because}, got {r.actual} {r.policies})"
        print(f"{mark} {r.name}{detail}")
    failed = sum(not r.passed for r in results)
    print(f"\n{len(results) - failed}/{len(results)} policy tests passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
