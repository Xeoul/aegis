"""Create the AWS side of the demo in LocalStack (or a sandbox account).

    docker compose up -d localstack
    AWS_ENDPOINT_URL=http://localhost:4566 python scripts/localstack_bootstrap.py

For every AWS-backed resource in seed_data.AWS_BACKING this creates the resource itself and an
IAM role that Aegis assumes. The role's own permissions are deliberately broad for the whole
resource: every session Aegis issues is narrowed by a session policy to the one granted action.
"""

import json
import os
import secrets
import sys
from pathlib import Path

import boto3

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from seed_data import AWS_BACKING, aws_config

REGION = os.getenv("AWS_REGION", "us-east-1")
os.environ.setdefault("AWS_ACCESS_KEY_ID", "test")
os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "test")


def trust_policy(account: str) -> str:
    # Whoever runs Aegis (its own IAM principal in a real deployment) may assume the role, set a
    # SourceIdentity and tag the session. Nothing else.
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
                    "Action": ["sts:AssumeRole", "sts:SetSourceIdentity", "sts:TagSession"],
                }
            ],
        }
    )


def main() -> None:
    iam = boto3.client("iam", region_name=REGION)
    account = boto3.client("sts", region_name=REGION).get_caller_identity()["Account"]
    os.environ["AEGIS_AWS_ACCOUNT_ID"] = account

    boto3.client("s3", region_name=REGION).create_bucket(Bucket="aegis-data-lake")
    boto3.client("dynamodb", region_name=REGION).create_table(
        TableName="customer-pii",
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        BillingMode="PAY_PER_REQUEST",
    )
    boto3.client("secretsmanager", region_name=REGION).create_secret(
        Name="payroll-db-credentials",
        SecretString=json.dumps({"user": "payroll", "password": secrets.token_urlsafe(24)}),
    )

    for name, (service, _, role_name) in AWS_BACKING.items():
        cfg = aws_config(name)
        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy(account), MaxSessionDuration=3600)
        resources = [cfg["aws_resource_arn"]] + ([f"{cfg['aws_resource_arn']}/*"] if service == "s3" else [])
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName="ResourceAccess",
            PolicyDocument=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": f"{service}:*", "Resource": resources}],
                }
            ),
        )
        print(f"{name:<18} {cfg['aws_role_arn']}")
    print(f"\nAccount {account}. Seed Aegis with: AEGIS_AWS_ACCOUNT_ID={account} python seed_data.py --reset")


if __name__ == "__main__":
    main()
