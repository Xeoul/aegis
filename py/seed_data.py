"""Populate the database with mock users and resources.

python seed_data.py            # add any missing seed rows (idempotent)
python seed_data.py --reset    # drop all tables first, then seed
"""

import argparse
import os

from sqlalchemy import select

from app import checkpoints
from app.database import Base, SessionLocal, engine, init_db
from app.models import Resource, SensitivityLevel, User

EMAIL_DOMAIN = "aegis.example"

USERS = [
    # name, department, role, is_admin, manager name
    ("Alice Chen", "Engineering", "engineer", False, "Maya Torres"),
    ("Bob Martinez", "Engineering", "sre", False, "Maya Torres"),
    ("Carol Singh", "Finance", "analyst", False, "Dan Okafor"),
    ("Dan Okafor", "Finance", "manager", False, None),
    ("Eve Johansson", "Security", "security engineer", False, None),
    ("Frank Lee", "Marketing", "intern", False, None),
    ("Grace Kim", "Compliance", "auditor", False, None),
    ("Hank Patel", "Engineering", "contractor", False, "Maya Torres"),
    # Identity administrator: can provision users but holds no special resource access.
    ("Iris Novak", "IT", "it admin", True, None),
    ("Maya Torres", "Engineering", "manager", False, None),
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
    ("s3-data-lake", SensitivityLevel.CONFIDENTIAL, "Engineering"),
]

# Resources backed by real AWS resources: grants on them can be exchanged for STS credentials.
# name -> (service, resource ARN template, IAM role name). {acct}/{region} are filled from the
# environment (LocalStack uses account 000000000000).
AWS_BACKING = {
    "s3-data-lake": ("s3", "arn:aws:s3:::aegis-data-lake", "aegis-jit-data-lake"),
    "customer-pii-db": ("dynamodb", "arn:aws:dynamodb:{region}:{acct}:table/customer-pii", "aegis-jit-customer-pii"),
    "payroll-system": (
        "secretsmanager",
        "arn:aws:secretsmanager:{region}:{acct}:secret:payroll-db-*",
        "aegis-jit-payroll",
    ),
}


def aws_config(name: str) -> dict[str, str | None]:
    if name not in AWS_BACKING:
        return {"aws_service": None, "aws_resource_arn": None, "aws_role_arn": None}
    acct = os.getenv("AEGIS_AWS_ACCOUNT_ID", "000000000000")
    region = os.getenv("AWS_REGION", "us-east-1")
    service, arn, role = AWS_BACKING[name]
    return {
        "aws_service": service,
        "aws_resource_arn": arn.format(acct=acct, region=region),
        "aws_role_arn": f"arn:aws:iam::{acct}:role/{role}",
    }


def seed(reset: bool = False) -> None:
    if reset:
        Base.metadata.drop_all(bind=engine)
        checkpoints.clear()  # they vouch for the log that was just dropped
    init_db()
    with SessionLocal() as db:
        existing_users = {u.email for u in db.scalars(select(User))}
        existing_resources = set(db.scalars(select(Resource.name)))
        db.add_all(
            User(name=n, email=email_for(n), department=d, role=r, is_admin=a)
            for n, d, r, a, _ in USERS
            if email_for(n) not in existing_users
        )
        db.flush()
        by_email = {u.email: u for u in db.scalars(select(User))}
        for n, *_, manager in USERS:
            if manager:
                by_email[email_for(n)].manager_id = by_email[email_for(manager)].id
        db.add_all(
            Resource(name=n, sensitivity_level=s, owner_department=o, **aws_config(n))
            for n, s, o in RESOURCES
            if n not in existing_resources
        )
        db.commit()

        print("Users:")
        for u in db.scalars(select(User).order_by(User.id)):
            extra = " (admin)" if u.is_admin else ""
            extra += f" reports to {u.manager_id}" if u.manager_id else ""
            print(f"  {u.id:>3}  {u.email:<28} {u.department:<12} {u.role}{extra}")
        print("\nResources:")
        for r in db.scalars(select(Resource).order_by(Resource.id)):
            aws = f"  [{r.aws_service}]" if r.aws_service else ""
            print(f"  {r.id:>3}  {r.name:<20} {r.sensitivity_level.value:<13} {r.owner_department or '-'}{aws}")
        print(
            "\nGet a token (dev mode):\n"
            "  curl -s localhost:8000/auth/dev-token -H 'content-type: application/json' "
            f'-d \'{{"email": "{email_for(USERS[0][0])}"}}\''
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--reset", action="store_true", help="drop and recreate all tables before seeding")
    seed(parser.parse_args().reset)
