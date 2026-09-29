import os
import tempfile

import pytest

_db_dir = tempfile.mkdtemp()
os.environ["AEGIS_DATABASE_URL"] = f"sqlite:///{_db_dir}/test.db"
os.environ["AEGIS_SCHEDULER_ENABLED"] = "false"
os.environ["AEGIS_LLM_MODE"] = "heuristic"

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402
from seed_data import seed  # noqa: E402


@pytest.fixture()
def client():
    seed(reset=True)
    with TestClient(app) as c:
        yield c
