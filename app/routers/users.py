from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit, workflow
from app.auth import get_current_user, require_admin
from app.database import get_db
from app.models import AuditEvent, Resource, User
from app.schemas import ResourceOut, UserCreate, UserOut, UserUpdate

router = APIRouter()

# Changing any of these can change what a user is entitled to, so open access is revoked
# and must be re-requested under the new attributes (mover handling).
ACCESS_RELEVANT = {"department", "role", "manager_id", "is_admin"}


def _check_manager(db: Session, manager_id: int | None, user_id: int | None = None) -> None:
    if manager_id is None:
        return
    if manager_id == user_id:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "A user cannot be their own manager")
    if db.get(User, manager_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, f"Manager {manager_id} does not exist")


@router.post("/users", response_model=UserOut, status_code=status.HTTP_201_CREATED, tags=["users"])
def create_user(payload: UserCreate, admin: User = Depends(require_admin), db: Session = Depends(get_db)) -> User:
    _check_manager(db, payload.manager_id)
    user = User(**payload.model_dump())
    db.add(user)
    try:
        db.flush()
    except IntegrityError as exc:
        raise HTTPException(status.HTTP_409_CONFLICT, f"A user with email {payload.email} already exists") from exc
    audit.record(
        db,
        AuditEvent.USER_CREATED,
        user_id=user.id,
        actor_id=admin.id,
        detail=f"Provisioned {user.email} ({user.department}/{user.role}, admin={user.is_admin}).",
    )
    audit.commit(db)
    return user


@router.patch("/users/{user_id}", response_model=UserOut, tags=["users"])
def update_user(
    user_id: int, payload: UserUpdate, admin: User = Depends(require_admin), db: Session = Depends(get_db)
) -> User:
    """Mover and leaver events. Admins cannot change their own record (no self-escalation)."""
    if user_id == admin.id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Administrators cannot modify their own account")
    user = db.get(User, user_id)
    if user is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"User {user_id} not found")

    changes = {k: v for k, v in payload.model_dump(exclude_unset=True).items() if getattr(user, k) != v}
    if "manager_id" in changes:
        _check_manager(db, changes["manager_id"], user.id)
    if not changes:
        return user
    summary = ", ".join(f"{k}: {getattr(user, k)!r} -> {v!r}" for k, v in changes.items())
    for key, value in changes.items():
        setattr(user, key, value)

    if changes.get("is_active") is False:
        audit.record(db, AuditEvent.USER_DEACTIVATED, user_id=user.id, actor_id=admin.id, detail=summary)
        workflow.revoke_all_for_user(db, user, admin.id, "Leaver: account deactivated.")
    else:
        audit.record(db, AuditEvent.USER_UPDATED, user_id=user.id, actor_id=admin.id, detail=summary)
        if ACCESS_RELEVANT & changes.keys():
            workflow.revoke_all_for_user(db, user, admin.id, f"Mover: access attributes changed ({summary}).")
    audit.commit(db)
    return user


@router.get("/users", response_model=list[UserOut], tags=["users"])
def list_users(_: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)))


@router.get("/resources", response_model=list[ResourceOut], tags=["resources"])
def list_resources(_: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Resource]:
    return list(db.scalars(select(Resource).order_by(Resource.id)))
