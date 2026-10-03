from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app import audit, identity
from app.auth import get_current_user, require_admin
from app.database import get_db
from app.models import AuditEvent, Resource, User
from app.schemas import ResourceOut, UserCreate, UserOut, UserUpdate

router = APIRouter()


def _check_manager(db: Session, manager_id: int | None, user_id: int | None = None) -> None:
    if error := identity.manager_error(db, manager_id, user_id):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_CONTENT, error)


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

    changes = payload.model_dump(exclude_unset=True)
    if "manager_id" in changes:
        _check_manager(db, changes["manager_id"], user.id)
    if identity.apply_changes(db, user, changes, admin.id):
        audit.commit(db)
    return user


@router.get("/users", response_model=list[UserOut], tags=["users"])
def list_users(_: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[User]:
    return list(db.scalars(select(User).order_by(User.id)))


@router.get("/resources", response_model=list[ResourceOut], tags=["resources"])
def list_resources(_: User = Depends(get_current_user), db: Session = Depends(get_db)) -> list[Resource]:
    return list(db.scalars(select(Resource).order_by(Resource.id)))
