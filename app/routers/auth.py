from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import config
from app.auth import create_dev_token, get_current_user
from app.database import get_db
from app.models import User
from app.schemas import DevTokenRequest, TokenOut, UserOut

router = APIRouter(tags=["auth"])


@router.post("/auth/dev-token", response_model=TokenOut)
def dev_token(payload: DevTokenRequest, db: Session = Depends(get_db)) -> TokenOut:
    """Stand-in identity provider for local development. Disabled when AEGIS_AUTH_MODE=oidc."""
    if config.settings.auth_mode != "dev":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or inactive user")
    token, ttl = create_dev_token(user)
    return TokenOut(access_token=token, expires_in=ttl)


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
