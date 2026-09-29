"""Attribute-based access control (ABAC) evaluation.

A request is ALLOWED only if every rule passes; each failing rule contributes a reason.

1. The resource must exist in the catalog.
2. Role clearance: the user's role must be cleared for the resource's sensitivity level.
3. Privileged actions: ``delete`` and ``admin`` require a privileged role.
4. Department boundary: confidential and restricted resources are limited to their owning
   department, except for cross-department roles (security, auditors).
5. Justification: restricted resources require a stated business reason.

Approved durations are capped per sensitivity level rather than denied outright.
"""

from dataclasses import dataclass, field

from app.models import Resource, SensitivityLevel, User
from app.schemas import Decision, ParsedPolicy

# Highest sensitivity each role may access. Unknown roles fall back to PUBLIC.
ROLE_CLEARANCE: dict[str, SensitivityLevel] = {
    "intern": SensitivityLevel.PUBLIC,
    "contractor": SensitivityLevel.INTERNAL,
    "analyst": SensitivityLevel.INTERNAL,
    "engineer": SensitivityLevel.CONFIDENTIAL,
    "manager": SensitivityLevel.CONFIDENTIAL,
    "auditor": SensitivityLevel.CONFIDENTIAL,
    "senior engineer": SensitivityLevel.RESTRICTED,
    "sre": SensitivityLevel.RESTRICTED,
    "security engineer": SensitivityLevel.RESTRICTED,
    "admin": SensitivityLevel.RESTRICTED,
}

PRIVILEGED_ACTIONS = {"delete", "admin"}
PRIVILEGED_ROLES = {"sre", "admin", "security engineer"}

# Roles whose job requires access across department boundaries.
CROSS_DEPARTMENT_ROLES = {"security engineer", "auditor", "admin"}
DEPARTMENT_BOUND_LEVELS = {SensitivityLevel.CONFIDENTIAL, SensitivityLevel.RESTRICTED}

MAX_DURATION_HOURS: dict[SensitivityLevel, int] = {
    SensitivityLevel.PUBLIC: 72,
    SensitivityLevel.INTERNAL: 24,
    SensitivityLevel.CONFIDENTIAL: 8,
    SensitivityLevel.RESTRICTED: 2,
}

NO_JUSTIFICATION = "no justification provided"


@dataclass
class EvaluationResult:
    decision: Decision
    reasons: list[str] = field(default_factory=list)
    granted_duration_hours: int = 0

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"


def _norm(value: str) -> str:
    return " ".join(value.strip().lower().replace("_", " ").split())


def evaluate(user: User, resource: Resource | None, policy: ParsedPolicy) -> EvaluationResult:
    if resource is None:
        return EvaluationResult("DENY", [f"Resource '{policy.resource}' is not in the resource catalog."])

    role = _norm(user.role)
    level = resource.sensitivity_level
    clearance = ROLE_CLEARANCE.get(role, SensitivityLevel.PUBLIC)
    denials: list[str] = []

    if clearance.rank < level.rank:
        denials.append(
            f"Role '{user.role}' is cleared up to {clearance.value}; '{resource.name}' is {level.value}."
        )

    if policy.action in PRIVILEGED_ACTIONS and role not in PRIVILEGED_ROLES:
        denials.append(
            f"Action '{policy.action}' is privileged and requires one of: {', '.join(sorted(PRIVILEGED_ROLES))}."
        )

    if (
        level in DEPARTMENT_BOUND_LEVELS
        and resource.owner_department
        and _norm(user.department) != _norm(resource.owner_department)
        and role not in CROSS_DEPARTMENT_ROLES
    ):
        denials.append(
            f"'{resource.name}' is {level.value} and restricted to the {resource.owner_department} "
            f"department; user is in {user.department}."
        )

    reason = policy.allow_reason.strip()
    if level == SensitivityLevel.RESTRICTED and (not reason or reason.lower().startswith(NO_JUSTIFICATION)):
        denials.append("Restricted resources require a business justification.")

    if denials:
        return EvaluationResult("DENY", denials)

    cap = MAX_DURATION_HOURS[level]
    requested = max(1, policy.duration_hours)
    granted = min(requested, cap)
    reasons = [
        f"Role '{user.role}' is cleared for {level.value} resources.",
        f"Action '{policy.action}' is permitted for this role.",
    ]
    if granted < requested:
        reasons.append(f"Duration reduced from {requested}h to the {level.value} maximum of {cap}h.")
    return EvaluationResult("ALLOW", reasons, granted)
