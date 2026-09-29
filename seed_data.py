"""Populate the database with mock users and resources.

    python seed_data.py            # add any missing seed rows (idempotent)
    python seed_data.py --reset    # drop all tables first, then seed
"""

import argparse

from sqlalchemy import select

from app.database import Base, SessionLocal, engine, init_db
from app.models import Resource, SensitivityLevel, User

EMAIL_DOMAIN = "aegis.example"

USERS = [
    # name, department, role, is_admin
    ("Alice Chen", "Engineering", "engineer", False),
    ("Bob Martinez", "Engineering", "sre", False),
    ("Carol Singh", "Finance", "analyst", False),
    ("Dan Okafor", "Finance", "manager", False),
    ("Eve Johansson", "Security", "security engineer", False),
    ("Frank Lee", "Marketing", "intern", False),
    ("Grace Kim", "Compliance", "auditor", False),
    ("Hank Patel", "Engineering", "contractor", False),
    # Identity administrator: can provision users but holds no special resource access.
    ("Iris Novak", "IT", "it admin", True),
]


def email_for(name: str) -> str:
    return f"{name.lower().replace(' ', '.')}@{EMAIL_DOMAIN}"

RESOURCES = [
    # name, sensitivity, owner department
    ("company-wiki", SensitivityLevel.PUBLIC, None),
    ("marketing-assets", SensitivityLevel.PUBLIC, "Marketing"),
    ("staging-cluster", SensitivityLevel.INTERNAL, "Engineering"),
    ("analytics-dashboard", SensitivityLevel.INTERNAL, None),
    ("ci-pipeline", SensitivityLevel.INTERNAL, "Engineering"),
    ("prod-db", SensitivityLevel.CONFIDENTIAL, "Engineering"),
    ("customer-pii-db", SensitivityLevel.CONFIDENTIAL, "Engineering"),
    ("payroll-system", SensitivityLevel.CONFIDENTIAL, "Finance"),
    ("prod-k8s-cluster", SensitivityLevel.RESTRICTED, "Engineering"),
    ("kms-master-keys", SensitivityLevel.RESTRICTED, "Security"),
]


def seed(reset: bool = False) -> None:
    if reset:
        Base.metadata.drop_all(bind=engine)
    init_db()
    with SessionLocal() as db:
        existing_users = {u.email for u in db.scalars(select(User))}
        existing_resources = set(db.scalars(select(Resource.name)))
        db.add_all(
            User(name=n, email=email_for(n), department=d, role=r, is_admin=a)
            for n, d, r, a in USERS
            if email_for(n) not in existing_users
        )
        db.add_all(
            Resource(name=n, sensitivity_level=s, owner_department=o)
            for n, s, o in RESOURCES
            if n not in existing_resources
        )
        db.commit()

        print("Users:")
        for u in db.scalars(select(User).order_by(User.id)):
            admin = " (admin)" if u.is_admin else ""
            print(f"  {u.id:>3}  {u.email:<28} {u.department:<12} {u.role}{admin}")
        print("\nResources:")
        for r in db.scalars(select(Resource).order_by(Resource.id)):
            print(f"  {r.id:>3}  {r.name:<20} {r.sensitivity_level.value:<13} {r.owner_department or '-'}")
        print(
            "\nGet a token (dev mode):\n"
            "  curl -s localhost:8000/auth/dev-token -H 'content-type: application/json' "
            f"-d '{{\"email\": \"{email_for(USERS[0][0])}\"}}'"
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="drop and recreate all tables before seeding")
    seed(parser.parse_args().reset)
