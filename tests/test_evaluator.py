import cedarpy
import pytest

from app.evaluator import POLICY_DIR, evaluate
from app.models import Resource, SensitivityLevel, User
from app.schemas import ParsedPolicy


def _policy(resource="r", action="read", hours=4, reason="Investigating incident INC-42"):
    return ParsedPolicy(resource=resource, action=action, allow_reason=reason, duration_hours=hours)


def _res(level, dept="Engineering"):
    return Resource(name="r", sensitivity_level=level, owner_department=dept)


def _user(role, dept="Engineering", active=True, uid=1):
    return User(id=uid, name="u", email=f"{uid}@aegis.example", department=dept, role=role, is_active=active)


ENGINEER = _user("engineer")


def test_policies_validate_against_schema():
    result = cedarpy.validate_policies((POLICY_DIR / "aegis.cedar").read_text(), (POLICY_DIR / "aegis.cedarschema").read_text())
    assert result.validation_passed, result.errors


def test_allow_within_clearance_and_department():
    result = evaluate(ENGINEER, _res(SensitivityLevel.CONFIDENTIAL), _policy())
    assert result.decision == "ALLOW" and not result.requires_approval
    assert result.granted_duration_hours == 4
    assert result.policy_ids == ["baseline-active-employee"]


def test_deny_unknown_resource():
    assert evaluate(ENGINEER, None, _policy(resource="unknown")).decision == "DENY"


def test_deny_insufficient_clearance():
    result = evaluate(ENGINEER, _res(SensitivityLevel.RESTRICTED), _policy())
    assert result.decision == "DENY"
    assert result.policy_ids == ["clearance"]
    assert "cleared up to confidential" in result.reasons[0]


def test_deny_privileged_action_for_non_privileged_role():
    result = evaluate(ENGINEER, _res(SensitivityLevel.INTERNAL), _policy(action="delete"))
    assert result.decision == "DENY" and "privileged-actions" in result.policy_ids


def test_deny_cross_department_confidential():
    result = evaluate(_user("manager", "Finance"), _res(SensitivityLevel.CONFIDENTIAL), _policy())
    assert result.decision == "DENY" and result.policy_ids == ["department-boundary"]


def test_department_match_is_case_insensitive():
    assert evaluate(_user("engineer", " engineering "), _res(SensitivityLevel.CONFIDENTIAL), _policy()).allowed


def test_cross_department_role_allowed():
    auditor = _user("auditor", "Compliance")
    assert evaluate(auditor, _res(SensitivityLevel.CONFIDENTIAL, "Finance"), _policy()).decision == "ALLOW"


def test_every_failing_guardrail_is_reported():
    intern = _user("intern", "Marketing")
    result = evaluate(intern, _res(SensitivityLevel.RESTRICTED), _policy(action="admin", reason="No justification provided"))
    assert set(result.policy_ids) >= {"clearance", "privileged-actions", "department-boundary", "justification-required"}
    assert not any("approval-required" in r for r in result.reasons)


def test_inactive_and_unknown_roles_fail_closed():
    assert evaluate(_user("engineer", active=False), _res(SensitivityLevel.PUBLIC), _policy()).decision == "DENY"
    unknown = evaluate(_user("wizard"), _res(SensitivityLevel.INTERNAL), _policy())
    assert unknown.decision == "DENY" and unknown.policy_ids == ["clearance"]


@pytest.mark.parametrize(
    "level, action",
    [(SensitivityLevel.RESTRICTED, "read"), (SensitivityLevel.INTERNAL, "delete"), (SensitivityLevel.PUBLIC, "admin")],
)
def test_high_risk_requires_approval_then_passes_when_approved(level, action):
    sre = _user("sre")
    pending = evaluate(sre, _res(level), _policy(action=action))
    assert pending.decision == "ALLOW" and pending.requires_approval
    assert pending.policy_ids == ["approval-required"]
    approved = evaluate(sre, _res(level), _policy(action=action), approved=True)
    assert approved.decision == "ALLOW" and not approved.requires_approval


def test_restricted_requires_justification_and_caps_duration():
    sre = _user("sre")
    level = SensitivityLevel.RESTRICTED
    denied = evaluate(sre, _res(level), _policy(reason="No justification provided"), approved=True)
    assert denied.decision == "DENY" and denied.policy_ids == ["justification-required"]
    result = evaluate(sre, _res(level), _policy(hours=12), approved=True)
    assert result.decision == "ALLOW"
    assert result.granted_duration_hours == 2
