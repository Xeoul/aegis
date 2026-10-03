"""Identity lifecycle shared by the admin API (``/users``) and SCIM provisioning (``/scim/v2``).

Whichever way a change arrives, it goes through :func:`apply_changes`, so a leaver deprovisioned
by an IdP over SCIM loses their grants and live cloud sessions exactly as if an administrator
had deactivated them by hand.
"""

from typing import Any

from sqlalchemy.orm import Session

from app import audit, workflow
from app.models import AuditEvent, User

# Changing any of these can change what a user is entitled to, so open access is revoked
# and must be re-requested under the new attributes (mover handling).
ACCESS_RELEVANT = {"department", "role", "manager_id", "is_admin"}


def manager_error(db: Session, manager_id: int | None, user_id: int | None = None) -> str | None:
    """Why ``manager_id`` can't be this user's manager, or None if it can."""
    if manager_id is None:
        return None
    if manager_id == user_id:
        return "A user cannot be their own manager"
    if db.get(User, manager_id) is None:
        return f"Manager {manager_id} does not exist"
    return None


def apply_changes(db: Session, user: User, changes: dict[str, Any], actor_id: int | None, *, via: str = "") -> bool:
    """Apply joiner/mover/leaver changes and record them. Returns False if nothing changed.

    The caller validates the values and commits the audit chain.
    """
    changes = {k: v for k, v in changes.items() if getattr(user, k) != v}
    if not changes:
        return False
    summary = ", ".join(f"{k}: {getattr(user, k)!r} -> {v!r}" for k, v in changes.items())
    if via:
        summary += f" ({via})"
    for key, value in changes.items():
        setattr(user, key, value)

    if changes.get("is_active") is False:
        audit.record(db, AuditEvent.USER_DEACTIVATED, user_id=user.id, actor_id=actor_id, detail=summary)
        workflow.revoke_all_for_user(db, user, actor_id, "Leaver: account deactivated.")
    else:
        audit.record(db, AuditEvent.USER_UPDATED, user_id=user.id, actor_id=actor_id, detail=summary)
        if ACCESS_RELEVANT & changes.keys():
            workflow.revoke_all_for_user(db, user, actor_id, f"Mover: access attributes changed ({summary}).")
    return True
