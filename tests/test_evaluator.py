from app.evaluator import evaluate
from app.models import Resource, SensitivityLevel, User
from app.schemas import ParsedPolicy


def _policy(resource="r", action="read", hours=4, reason="Investigating incident INC-42"):
    return ParsedPolicy(resource=resource, action=action, allow_reason=reason, duration_hours=hours)


def _res(level, dept="Engineering"):
    return Resource(name="r", sensitivity_level=level, owner_department=dept)


ENGINEER = User(id=1, name="a", department="Engineering", role="engineer")


def test_allow_within_clearance_and_department():
    result = evaluate(ENGINEER, _res(SensitivityLevel.CONFIDENTIAL), _policy())
    assert result.decision == "ALLOW"
    assert result.granted_duration_hours == 4


def test_deny_unknown_resource():
    assert evaluate(ENGINEER, None, _policy(resource="unknown")).decision == "DENY"


def test_deny_insufficient_clearance():
    result = evaluate(ENGINEER, _res(SensitivityLevel.RESTRICTED), _policy())
    assert result.decision == "DENY"
    assert "cleared up to confidential" in result.reasons[0]


def test_deny_privileged_action_for_non_privileged_role():
    assert evaluate(ENGINEER, _res(SensitivityLevel.INTERNAL), _policy(action="delete")).decision == "DENY"


def test_deny_cross_department_confidential():
    analyst = User(id=2, name="c", department="Finance", role="manager")
    assert evaluate(analyst, _res(SensitivityLevel.CONFIDENTIAL), _policy()).decision == "DENY"


def test_cross_department_role_allowed():
    auditor = User(id=3, name="g", department="Compliance", role="auditor")
    assert evaluate(auditor, _res(SensitivityLevel.CONFIDENTIAL, "Finance"), _policy()).decision == "ALLOW"


def test_restricted_requires_justification_and_caps_duration():
    sre = User(id=4, name="b", department="Engineering", role="sre")
    level = SensitivityLevel.RESTRICTED
    assert evaluate(sre, _res(level), _policy(reason="No justification provided")).decision == "DENY"
    result = evaluate(sre, _res(level), _policy(hours=12))
    assert result.decision == "ALLOW"
    assert result.granted_duration_hours == 2
