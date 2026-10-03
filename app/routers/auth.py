from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app import audit, config, mfa, ratelimit
from app.auth import create_dev_token, get_current_user, has_fresh_mfa
from app.database import get_db, utcnow
from app.models import Alert, AlertSeverity, AuditEvent, User
from app.schemas import DevTokenRequest, MfaEnrollOut, StepUpIn, TokenOut, UserOut

router = APIRouter(tags=["auth"])


def _dev_only() -> None:
    # In oidc mode the IdP owns sign-in and MFA; these endpoints don't exist.
    if config.settings.auth_mode != "dev":
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Not found")


@router.post("/auth/dev-token", response_model=TokenOut, dependencies=[Depends(ratelimit.sign_in)])
def dev_token(payload: DevTokenRequest, db: Session = Depends(get_db)) -> TokenOut:
    """Stand-in identity provider for local development. Disabled when AEGIS_AUTH_MODE=oidc."""
    _dev_only()
    user = db.scalar(select(User).where(User.email == payload.email.lower()))
    if user is None or not user.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Unknown or inactive user")
    token, ttl = create_dev_token(user)
    return TokenOut(access_token=token, expires_in=ttl)


@router.post("/auth/mfa/enroll", response_model=MfaEnrollOut, dependencies=[Depends(_dev_only)])
def enroll_mfa(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> MfaEnrollOut:
    """Start (or restart) TOTP enrollment. The secret is confirmed by the first step-up.

    Replacing a confirmed authenticator needs a fresh MFA sign-in, so someone holding only a
    stolen session token can't swap in their own authenticator.
    """
    if user.totp_confirmed and not has_fresh_mfa(request):
        raise mfa.step_up_required("Replacing your authenticator needs a recent sign-in with the current one.")
    if user.totp_failures >= mfa.MAX_FAILURES:
        raise HTTPException(status.HTTP_423_LOCKED, "Your authenticator is locked; ask an administrator to reset it")
    user.totp_secret = mfa.new_secret()
    user.totp_confirmed = False
    user.totp_last_step = None
    db.commit()
    return MfaEnrollOut(secret=user.totp_secret, otpauth_uri=mfa.otpauth_uri(user.totp_secret, user.email))


@router.post("/auth/step-up", response_model=TokenOut, dependencies=[Depends(_dev_only), Depends(ratelimit.mfa_codes)])
def step_up(payload: StepUpIn, user: User = Depends(get_current_user), db: Session = Depends(get_db)) -> TokenOut:
    """Verify a TOTP code and issue a token that records the second factor (amr, acr, auth_time)."""
    if user.totp_secret is None:
        raise HTTPException(status.HTTP_409_CONFLICT, "No authenticator enrolled; POST /auth/mfa/enroll first")
    if user.totp_failures >= mfa.MAX_FAILURES:
        raise HTTPException(status.HTTP_423_LOCKED, "Your authenticator is locked; ask an administrator to reset it")

    now = utcnow()
    step = mfa.verify(user.totp_secret, payload.code, now, user.totp_last_step)
    if step is None:
        user.totp_failures += 1
        audit.record(
            db,
            AuditEvent.MFA_FAILED,
            user_id=user.id,
            actor_id=user.id,
            detail=f"Wrong or reused code ({user.totp_failures} of {mfa.MAX_FAILURES}).",
        )
        if user.totp_failures == mfa.MAX_FAILURES:
            _raise_lockout_alert(db, user)
        audit.commit(db)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "That code is wrong or was already used")

    first = not user.totp_confirmed
    user.totp_confirmed, user.totp_last_step, user.totp_failures = True, step, 0
    audit.record(
        db,
        AuditEvent.MFA_ENROLLED if first else AuditEvent.MFA_VERIFIED,
        user_id=user.id,
        actor_id=user.id,
        detail="TOTP authenticator confirmed." if first else "Stepped up with TOTP.",
    )
    audit.commit(db)
    token, ttl = create_dev_token(user, mfa_at=now)
    return TokenOut(access_token=token, expires_in=ttl)


def _raise_lockout_alert(db: Session, user: User) -> None:
    alert = Alert(
        created_at=utcnow(),
        rule="mfa-brute-force",
        severity=AlertSeverity.HIGH,
        user_id=user.id,
        detail=f"{mfa.MAX_FAILURES} wrong MFA codes in a row; the authenticator is locked until an admin resets it.",
    )
    db.add(alert)
    db.flush()
    audit.record(
        db,
        AuditEvent.ALERT_RAISED,
        user_id=user.id,
        detail=f"alert={alert.id} rule=mfa-brute-force severity=high: {alert.detail}",
    )


@router.get("/me", response_model=UserOut)
def me(user: User = Depends(get_current_user)) -> User:
    return user
