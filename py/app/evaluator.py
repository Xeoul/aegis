"""Attribute-based access control, evaluated by the Cedar policy engine.

The rules live in ``policies/aegis.cedar`` (validated against ``policies/aegis.cedarschema``)
and role attributes in ``policies/attributes.json``. This module only translates Aegis
objects into Cedar entities, asks Cedar for a decision, and turns the policies that determined
it into readable reasons.

Outcomes:

* Cedar ALLOW: grant immediately.
* Cedar DENY where the only matching forbid is ``approval-required``: the request is allowed
  but needs a second person. At approval time it is re-evaluated with ``approved=True``.
* Any other DENY: denied, with one reason per guardrail that fired.

Granted durations are capped per sensitivity level rather than denied outright.
"""

import json
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any

import cedarpy

from app.models import Resource, SensitivityLevel, User
from app.schemas import Decision, ParsedPolicy

POLICY_DIR = Path(__file__).resolve().parent.parent / "policies"
APPROVAL_POLICY_ID = "approval-required"
MFA_POLICY_ID = "mfa-required"
NO_JUSTIFICATION = "no justification provided"

# Emergency (break-glass) grants skip approval, so they are kept very short.
BREAK_GLASS_MAX_HOURS = 1


@dataclass
class EvaluationResult:
    decision: Decision
    reasons: list[str] = field(default_factory=list)
    granted_duration_hours: int = 0
    requires_approval: bool = False
    policy_ids: list[str] = field(default_factory=list)
    # Only the mfa-required guardrail (and possibly approval) stands in the way: the caller
    # should step up with a second factor and retry, rather than be denied.
    step_up_required: bool = False

    @property
    def allowed(self) -> bool:
        return self.decision == "ALLOW"


@dataclass(frozen=True)
class PolicyBundle:
    policies: Any  # cedarpy.PolicySet
    schema: Any  # cedarpy.Schema
    annotations: dict[str, dict[str, str]]  # Cedar-internal policy id -> {"id", "reason"}
    roles: dict[str, dict[str, Any]]
    default_role: dict[str, Any]
    max_duration_hours: dict[SensitivityLevel, int]


class PolicyError(RuntimeError):
    pass


def normalize(value: str) -> str:
    return " ".join(value.strip().lower().replace("_", " ").split())


@lru_cache(maxsize=1)
def load_policies() -> PolicyBundle:
    """Parse and validate the policy bundle once. Invalid policies fail closed at startup."""
    policy_text = (POLICY_DIR / "aegis.cedar").read_text()
    schema_text = (POLICY_DIR / "aegis.cedarschema").read_text()
    validation = cedarpy.validate_policies(policy_text, schema_text)
    if not validation.validation_passed:
        raise PolicyError(f"Cedar policies failed schema validation: {validation.errors}")
    static = json.loads(cedarpy.policies_to_json_str(policy_text))["staticPolicies"]
    attributes = json.loads((POLICY_DIR / "attributes.json").read_text())
    return PolicyBundle(
        policies=cedarpy.PolicySet.from_str(policy_text),
        schema=cedarpy.Schema.from_str(schema_text),
        annotations={pid: p.get("annotations", {}) for pid, p in static.items()},
        roles={normalize(k): v for k, v in attributes["roles"].items()},
        default_role=attributes["default_role"],
        max_duration_hours={SensitivityLevel(k): v for k, v in attributes["max_duration_hours"].items()},
    )


def _entities(user: User, resource: Resource, bundle: PolicyBundle) -> tuple[list[dict], str]:
    role_key = normalize(user.role)
    role_id = role_key if role_key in bundle.roles else "__default__"
    role_attrs = bundle.roles.get(role_key, bundle.default_role)
    resource_attrs: dict[str, Any] = {"sensitivity": resource.sensitivity_level.rank}
    if resource.owner_department:
        resource_attrs["owner_department"] = normalize(resource.owner_department)
    role_uid = {"type": "Role", "id": role_id}
    return [
        {"uid": role_uid, "attrs": role_attrs, "parents": []},
        {
            "uid": {"type": "User", "id": str(user.id)},
            "attrs": {
                "role": {"__entity": role_uid},
                "department": normalize(user.department),
                "active": bool(user.is_active),
            },
            "parents": [role_uid],
        },
        {"uid": {"type": "Resource", "id": resource.name}, "attrs": resource_attrs, "parents": []},
    ], role_id


def _detail(policy_id: str, user: User, resource: Resource, policy: ParsedPolicy, clearance: int) -> str:
    level = resource.sensitivity_level
    cleared = list(SensitivityLevel)[max(clearance, 1) - 1].value
    return {
        "clearance": f"Role '{user.role}' is cleared up to {cleared}; '{resource.name}' is {level.value}.",
        "privileged-actions": f"Role '{user.role}' may not perform '{policy.action}'.",
        "department-boundary": f"'{resource.name}' belongs to {resource.owner_department}; "
        f"requester is in {user.department}.",
        "baseline-active-employee": "Requester is an active employee.",
    }.get(policy_id, "")


def _source_order(policy_id: str) -> tuple[int, str]:
    # Cedar numbers policies policy0, policy1, ... in the order they appear in the file.
    number = policy_id.removeprefix("policy")
    return (int(number), "") if number.isdigit() else (1 << 30, policy_id)


def evaluate(
    user: User,
    resource: Resource | None,
    policy: ParsedPolicy,
    *,
    approved: bool = False,
    mfa: bool = False,
    break_glass: bool = False,
) -> EvaluationResult:
    if resource is None:
        return EvaluationResult("DENY", [f"Resource '{policy.resource}' is not in the resource catalog."])

    bundle = load_policies()
    entities, role_id = _entities(user, resource, bundle)
    reason = policy.allow_reason.strip()
    result = cedarpy.is_authorized(
        {
            "principal": {"type": "User", "id": str(user.id)},
            "action": {"type": "Action", "id": policy.action},
            "resource": {"type": "Resource", "id": resource.name},
            "context": {
                "has_justification": bool(reason) and not reason.lower().startswith(NO_JUSTIFICATION),
                "approved": approved,
                "mfa": mfa,
                "break_glass": break_glass,
            },
        },
        bundle.policies,
        entities,
        schema=bundle.schema,
    )
    if result.diagnostics.errors:
        # Evaluation errors mean a policy could not be applied; fail closed.
        return EvaluationResult("DENY", [f"Policy evaluation error: {result.diagnostics.errors}"])

    clearance = bundle.roles.get(role_id, bundle.default_role)["clearance"]
    # Report reasons in policy-file order. Cedar returns them as a set, and the native and
    # WebAssembly builds order that set differently.
    determining = [bundle.annotations.get(pid, {}) for pid in sorted(result.diagnostics.reasons, key=_source_order)]
    ids = [a.get("id", "?") for a in determining]

    def explain(annotation: dict[str, str]) -> str:
        detail = _detail(annotation.get("id", ""), user, resource, policy, clearance)
        return f"[{annotation.get('id')}] {annotation.get('reason', '')} {detail}".strip()

    requires_approval = False
    if not result.allowed:
        # approval-required and mfa-required are not reasons to deny: one routes the request to
        # an approver, the other asks for step-up. They're reported only when nothing else fires.
        blocking = [a for a in determining if a.get("id") not in (APPROVAL_POLICY_ID, MFA_POLICY_ID)]
        if ids and not blocking and MFA_POLICY_ID in ids:
            return EvaluationResult(
                "DENY",
                [explain(a) for a in determining if a.get("id") == MFA_POLICY_ID],
                requires_approval=APPROVAL_POLICY_ID in ids,
                policy_ids=[MFA_POLICY_ID],
                step_up_required=True,
            )
        if ids == [APPROVAL_POLICY_ID]:
            requires_approval = True
        else:
            return EvaluationResult(
                "DENY",
                [explain(a) for a in blocking] or ["No policy permits this request."],
                policy_ids=[a.get("id", "?") for a in blocking],
            )

    cap = bundle.max_duration_hours[resource.sensitivity_level]
    requested = max(1, policy.duration_hours)
    granted = min(requested, cap)
    reasons = [explain(a) for a in determining]
    if granted < requested:
        reasons.append(
            f"Duration reduced from {requested}h to the {resource.sensitivity_level.value} maximum of {cap}h."
        )
    return EvaluationResult("ALLOW", reasons, granted, requires_approval, ids)
