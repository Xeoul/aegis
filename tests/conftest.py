import os
import tempfile

import pytest

_db_dir = tempfile.mkdtemp()
os.environ["AEGIS_DATABASE_URL"] = f"sqlite:///{_db_dir}/test.db"
os.environ["AEGIS_SCHEDULER_ENABLED"] = "false"
os.environ["AEGIS_LLM_MODE"] = "heuristic"
os.environ["AEGIS_AUTH_MODE"] = "dev"
os.environ["AEGIS_AUDIT_KEY"] = "test-audit-key"
# Treat every moment as business hours so the off-hours rule only fires in tests that want it.
os.environ["AEGIS_BUSINESS_HOURS_UTC"] = "00-24"
os.environ["AEGIS_BUSINESS_DAYS"] = "0-6"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from seed_data import email_for, seed  # noqa: E402

ALICE = email_for("Alice Chen")  # Engineering engineer
BOB = email_for("Bob Martinez")  # Engineering sre
FRANK = email_for("Frank Lee")  # Marketing intern
GRACE = email_for("Grace Kim")  # Compliance auditor
IRIS = email_for("Iris Novak")  # IT admin (identity administrator)
MAYA = email_for("Maya Torres")  # Engineering manager; manages Alice, Bob, Hank
EVE = email_for("Eve Johansson")  # Security engineer
DAN = email_for("Dan Okafor")  # Finance manager
HANK = email_for("Hank Patel")  # Engineering contractor


@pytest.fixture()
def client():
    seed(reset=True)
    with TestClient(app) as c:
        yield c


@pytest.fixture()
def auth(client):
    """auth(email) -> headers carrying a bearer token for that seeded user."""

    def _headers(email: str) -> dict[str, str]:
        resp = client.post("/auth/dev-token", json={"email": email})
        assert resp.status_code == 200, resp.text
        return {"Authorization": f"Bearer {resp.json()['access_token']}"}

    return _headers
