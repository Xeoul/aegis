"""Populate the database with mock users and resources.

    python seed_data.py            # add any missing seed rows (idempotent)
    python seed_data.py --reset    # drop all tables first, then seed
"""

import argparse

from sqlalchemy import select

from app.database import Base, SessionLocal, engine, init_db
from app.models import Resource, SensitivityLevel, User

USERS = [
    # name, department, role
    ("Alice Chen", "Engineering", "engineer"),
    ("Bob Martinez", "Engineering", "sre"),
    ("Carol Singh", "Finance", "analyst"),
    ("Dan Okafor", "Finance", "manager"),
    ("Eve Johansson", "Security", "security engineer"),
    ("Frank Lee", "Marketing", "intern"),
    ("Grace Kim", "Compliance", "auditor"),
    ("Hank Patel", "Engineering", "contractor"),
]

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
        existing_users = {u.name for u in db.scalars(select(User))}
        existing_resources = set(db.scalars(select(Resource.name)))
        db.add_all(
            User(name=n, department=d, role=r) for n, d, r in USERS if n not in existing_users
        )
        db.add_all(
            Resource(name=n, sensitivity_level=s, owner_department=o)
            for n, s, o in RESOURCES
            if n not in existing_resources
        )
        db.commit()

        print("Users:")
        for u in db.scalars(select(User).order_by(User.id)):
            print(f"  {u.id:>3}  {u.name:<16} {u.department:<12} {u.role}")
        print("\nResources:")
        for r in db.scalars(select(Resource).order_by(Resource.id)):
            print(f"  {r.id:>3}  {r.name:<20} {r.sensitivity_level.value:<13} {r.owner_department or '-'}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="drop and recreate all tables before seeding")
    seed(parser.parse_args().reset)
