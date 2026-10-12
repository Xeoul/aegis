"""In-process rate limits for the endpoints worth abusing.

A token bucket per caller and endpoint: sign-in, MFA codes, access requests (each one may
call the LLM) and policy simulation. Over the limit, the API answers 429 with Retry-After,
and the first refusal in each window is audited, so a flood can't also flood the audit log.

This is per process. Behind a load balancer with several instances, put the same limits at
the gateway (or back them with Redis); ``AEGIS_RATE_LIMITS=false`` turns these off.
"""

import math
import threading
import time
from collections import OrderedDict
from collections.abc import Callable

from fastapi import Depends, HTTPException, Request, status

from app import audit
from app.auth import get_current_user
from app.config import settings
from app.database import SessionLocal
from app.models import AuditEvent, User

MAX_KEYS = 10_000  # oldest buckets are dropped beyond this, so memory stays bounded


class TokenBucket:
    def __init__(self, capacity: int, per_seconds: float):
        self.capacity = capacity
        self.rate = capacity / per_seconds
        self._buckets: OrderedDict[str, tuple[float, float, bool]] = OrderedDict()
        self._lock = threading.Lock()

    def take(self, key: str, now: float | None = None) -> tuple[bool, float, bool]:
        """Spend one token. Returns (allowed, seconds until a token is free, first refusal)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            tokens, last, refused = self._buckets.pop(key, (float(self.capacity), now, False))
            tokens = min(self.capacity, tokens + (now - last) * self.rate)
            if tokens >= 1:
                self._buckets[key] = (tokens - 1, now, False)
                allowed, wait, first = True, 0.0, False
            else:
                self._buckets[key] = (tokens, now, True)
                allowed, wait, first = False, (1 - tokens) / self.rate, not refused
            while len(self._buckets) > MAX_KEYS:
                self._buckets.popitem(last=False)
        return allowed, wait, first

    def reset(self) -> None:
        with self._lock:
            self._buckets.clear()


_limits: list[TokenBucket] = []


def reset_all() -> None:
    for bucket in _limits:
        bucket.reset()


def _refuse(name: str, wait: float, first: bool, user_id: int | None, who: str) -> HTTPException:
    if first:
        with SessionLocal() as db:
            audit.record(db, AuditEvent.RATE_LIMITED, user_id=user_id, actor_id=user_id, detail=f"{name}: {who}")
            audit.commit(db)
    return HTTPException(
        status.HTTP_429_TOO_MANY_REQUESTS,
        f"Too many {name} requests; try again in {math.ceil(wait)}s",
        headers={"Retry-After": str(math.ceil(wait))},
    )


def per_user(name: str, capacity: int, per_seconds: float) -> Callable[..., None]:
    """A dependency limiting each signed-in user to ``capacity`` calls per ``per_seconds``."""
    bucket = TokenBucket(capacity, per_seconds)
    _limits.append(bucket)

    def check(user: User = Depends(get_current_user)) -> None:
        if not settings.rate_limits:
            return
        allowed, wait, first = bucket.take(f"user:{user.id}")
        if not allowed:
            raise _refuse(name, wait, first, user.id, user.email)

    return check


def per_client(name: str, capacity: int, per_seconds: float) -> Callable[..., None]:
    """A dependency limiting each client address, for endpoints called before sign-in."""
    bucket = TokenBucket(capacity, per_seconds)
    _limits.append(bucket)

    def check(request: Request) -> None:
        if not settings.rate_limits:
            return
        client = request.client.host if request.client else "unknown"
        allowed, wait, first = bucket.take(f"ip:{client}")
        if not allowed:
            raise _refuse(name, wait, first, None, client)

    return check


sign_in = per_client("sign-in", 30, 60)
mfa_codes = per_user("MFA code", 10, 60)
access_requests = per_user("access", 30, 60)
simulations = per_user("simulation", 60, 60)
