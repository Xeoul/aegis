"""Policy tooling for the security team: what-if simulation and the policy test suite."""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, policy_tests
from app.auth import require_oversight
from app.database import get_db
from app.evaluator import evaluate
from app.models import AuditEvent, Resource, User
from app.schemas import ParsedPolicy, PolicyTestsOut, SimulateIn, SimulateOut

router = APIRouter(prefix="/policy", tags=["policy"])


@router.post("/simulate", response_model=SimulateOut)
def simulate(
    payload: SimulateIn, analyst: User = Depends(require_oversight), db: Session = Depends(get_db)
) -> SimulateOut:
    """Ask the real policy engine what it would decide, without granting or storing anything.

    The person and resource are copied before overrides are applied, so a what-if never
    changes a stored attribute. The question itself is audited: knowing who probed the policy
    for which access is useful in an investigation.
    """
    user = db.get(User, payload.user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"User {payload.user_id} not found")
    stored = db.scalar(select(Resource).where(Resource.name == payload.resource))
    if stored is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Resource '{payload.resource}' is not in the catalog")

    person = User(
        id=user.id,
        name=user.name,
        email=user.email,
        role=payload.role or user.role,
        department=payload.department or user.department,
        is_active=user.is_active,
    )
    resource = Resource(
        name=stored.name,
        sensitivity_level=payload.sensitivity or stored.sensitivity_level,
        owner_department=stored.owner_department,
    )
    result = evaluate(
        person,
        resource,
        ParsedPolicy(
            resource=resource.name,
            action=payload.action,
            allow_reason=payload.justification,
            duration_hours=payload.duration_hours,
        ),
        approved=payload.approved,
        mfa=payload.mfa,
        break_glass=payload.break_glass,
    )
    outcome = policy_tests.outcome(result)
    overrides = {
        k: v
        for k, v in (("role", payload.role), ("department", payload.department), ("sensitivity", payload.sensitivity))
        if v
    }
    audit.record(
        db,
        AuditEvent.POLICY_SIMULATED,
        user_id=user.id,
        actor_id=analyst.id,
        resource=resource.name,
        action=payload.action,
        detail=f"What-if for {user.email}: {outcome}" + (f" with {overrides}" if overrides else ""),
    )
    audit.commit(db)
    return SimulateOut(
        outcome=outcome,
        decision=result.decision,
        reasons=result.reasons,
        policy_ids=result.policy_ids,
        granted_duration_hours=result.granted_duration_hours,
        role=person.role,
        department=person.department,
        sensitivity=resource.sensitivity_level,
        owner_department=resource.owner_department,
    )


@router.get("/tests", response_model=PolicyTestsOut, dependencies=[Depends(require_oversight)])
def run_policy_tests() -> PolicyTestsOut:
    """Run policies/tests.json against the loaded policies."""
    results = policy_tests.run_all()
    passed = sum(r.passed for r in results)
    return PolicyTestsOut.model_validate(
        {"passed": passed, "failed": len(results) - passed, "cases": [r.as_dict() for r in results]}
    )
