"""The declarative policy test suite, and what-if simulation."""

import pytest
from conftest import ALICE, BOB, GRACE

from app import policy_tests

CASES = policy_tests.load_cases()


@pytest.mark.parametrize("case", CASES, ids=[c["name"] for c in CASES])
def test_policy_case(case):
    result = policy_tests.run_case(case)
    assert result.passed, result


def test_cases_use_known_outcomes():
    assert {c["expect"] for c in CASES} <= set(policy_tests.OUTCOMES)
    assert len({c["name"] for c in CASES}) == len(CASES)


def test_runner_reports_a_wrong_expectation():
    case = {**CASES[0], "expect": "deny"}
    assert not policy_tests.run_case(case).passed
    assert policy_tests.main() == 0


def _ids(client, auth):
    users = {u["email"]: u["id"] for u in client.get("/users", headers=auth(GRACE)).json()}
    return users[ALICE], users[BOB]


def _simulate(client, auth, **body):
    return client.post("/policy/simulate", json=body, headers=auth(GRACE))


def test_simulation_is_oversight_only(client, auth):
    alice, _ = _ids(client, auth)
    body = {"user_id": alice, "resource": "prod-db", "action": "read"}
    assert client.post("/policy/simulate", json=body, headers=auth(ALICE)).status_code == 403
    assert client.get("/policy/tests", headers=auth(ALICE)).status_code == 403


def test_what_if_a_mover(client, auth):
    alice, _ = _ids(client, auth)
    now = _simulate(client, auth, user_id=alice, resource="prod-db", action="read").json()
    assert now["outcome"] == "allow" and now["department"] == "Engineering"
    moved = _simulate(client, auth, user_id=alice, resource="prod-db", action="read", department="Finance").json()
    assert moved["outcome"] == "deny" and moved["policy_ids"] == ["department-boundary"]
    # Nothing changed for real, and nothing was granted.
    me = client.get("/me", headers=auth(ALICE)).json()
    assert me["department"] == "Engineering"
    assert client.get("/requests", headers=auth(ALICE)).json() == []


def test_what_if_reclassified_and_without_mfa(client, auth):
    _, bob = _ids(client, auth)
    restricted = _simulate(
        client, auth, user_id=bob, resource="prod-db", action="read", sensitivity="restricted"
    ).json()
    assert restricted["outcome"] == "needs-approval" and restricted["granted_duration_hours"] == 1
    no_mfa = _simulate(client, auth, user_id=bob, resource="prod-k8s-cluster", action="admin", mfa=False).json()
    assert no_mfa["outcome"] == "step-up" and no_mfa["policy_ids"] == ["mfa-required"]
    approved = _simulate(
        client, auth, user_id=bob, resource="prod-k8s-cluster", action="admin", approved=True, duration_hours=8
    ).json()
    assert approved["outcome"] == "allow" and approved["granted_duration_hours"] == 2


def test_simulations_are_audited_and_validated(client, auth):
    alice, _ = _ids(client, auth)
    _simulate(client, auth, user_id=alice, resource="prod-db", action="read", role="intern")
    logs = client.get("/audit-logs", params={"event": "POLICY_SIMULATED"}, headers=auth(GRACE)).json()
    assert logs and "deny" in logs[0]["detail"] and "intern" in logs[0]["detail"]
    assert _simulate(client, auth, user_id=999, resource="prod-db", action="read").status_code == 404
    assert _simulate(client, auth, user_id=alice, resource="nope", action="read").status_code == 404
    assert _simulate(client, auth, user_id=alice, resource="prod-db", action="sudo").status_code == 422


def test_policy_tests_endpoint(client, auth):
    body = client.get("/policy/tests", headers=auth(GRACE)).json()
    assert body["failed"] == 0 and body["passed"] == len(CASES)
