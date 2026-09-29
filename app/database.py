"""SQLite engine, session factory and declarative base."""

import os
from collections.abc import Iterator
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

DATABASE_URL = os.getenv("AEGIS_DATABASE_URL", "sqlite:///./aegis_jit.db")

engine = create_engine(
    DATABASE_URL,
    # FastAPI serves requests and APScheduler runs jobs on different threads.
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {},
)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


def utcnow() -> datetime:
    """Naive UTC timestamp. SQLite has no timezone type, so everything is stored as naive UTC."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def init_db() -> None:
    from app import models  # noqa: F401  (registers the tables on Base.metadata)

    Base.metadata.create_all(bind=engine)


def get_db() -> Iterator[Session]:
    """FastAPI dependency that yields a session and always closes it."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
