import pytest

from app.llm_parser import heuristic_parse

CATALOG = ["prod-db", "prod-db-replica", "staging-cluster", "payroll-system", "kms-master-keys"]


@pytest.mark.parametrize(
    "text, resource, action, hours",
    [
        ("I need read access to prod-db for 4 hours to debug a failing migration", "prod-db", "read", 4),
        ("Please give me write access on the staging cluster for 2 days", "staging-cluster", "write", 48),
        ("Need to query prod-db-replica for 30 minutes", "prod-db-replica", "read", 1),
        ("drop old tables in prod-db, an hour is enough", "prod-db", "delete", 1),
        ("sudo on kms-master-keys until end of day because of key rotation", "kms-master-keys", "admin", 8),
        ("let me look at the billing system", "unknown", "read", 1),
    ],
)
def test_heuristic_parse(text, resource, action, hours):
    policy = heuristic_parse(text, CATALOG)
    assert (policy.resource, policy.action, policy.duration_hours) == (resource, action, hours)


def test_heuristic_reason():
    policy = heuristic_parse("I need read access to prod-db for 4 hours to debug a failing migration", CATALOG)
    assert policy.allow_reason == "Debug a failing migration"
    policy = heuristic_parse("sudo on kms-master-keys because of the quarterly key rotation", CATALOG)
    assert policy.allow_reason == "Quarterly key rotation"


@pytest.mark.parametrize("payload", ["9" * 20_000, "9." * 10_000, "1 " * 10_000 + "x"])
def test_duration_parsing_is_linear_time(payload):
    """Regression for CodeQL py/polynomial-redos on user-controlled request text."""
    import time

    from app.llm_parser import _clean_reason, _extract_duration

    start = time.perf_counter()
    _extract_duration(payload)
    _clean_reason(payload)
    heuristic_parse(payload, CATALOG)
    assert time.perf_counter() - start < 0.5
