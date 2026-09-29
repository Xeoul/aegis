"""The live demo's bridge (demo/bridge.py) drives the real app the way the web page does.

It swaps modules and settings at import, so it runs in its own interpreter rather than
alongside the rest of the suite.
"""

import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SCENARIO = textwrap.dedent(
    """
    import asyncio, json, sys
    from datetime import datetime, timedelta
    sys.path[:0] = [ROOT, ROOT + "/demo"]
    import bridge

    # The browser has no threads or multiprocessing: the bridge must not need APScheduler.
    assert getattr(sys.modules["apscheduler.schedulers.background"], "__file__", None) is None

    async def api(method, path, token=None, body=None):
        r = json.loads(await bridge.call(method, path, token, json.dumps(body) if body is not None else None))
        return r["status"], r["body"]

    async def token(email):
        status, body = await api("POST", "/auth/dev-token", body={"email": email})
        assert status == 200, body
        return body["access_token"]

    async def ask(email, text, break_glass=False):
        status, body = await api("POST", "/request-access", await token(email),
                                 {"request_text": text, "break_glass": break_glass})
        assert status == 200, body
        return body

    async def main():
        people = {p["name"]: p["email"] for p in json.loads(bridge.users())}
        alice, bob, frank, grace, maya = (people[n] for n in
            ("Alice Chen", "Bob Martinez", "Frank Lee", "Grace Kim", "Maya Torres"))

        d = await ask(alice, "Read access to prod-db for 4 hours to debug a failing migration")
        assert (d["decision"], d["status"], d["parser"]) == ("ALLOW", "ACTIVE", "heuristic"), d
        d = await ask(frank, "let me edit payroll-system for a day")
        assert (d["decision"], d["status"]) == ("DENY", "DENIED"), d
        pending = await ask(bob, "Need admin on prod-k8s-cluster for 6 hours to roll back a bad deploy")
        assert pending["status"] == "PENDING_APPROVAL" and pending["policy"]["conditions"]["duration_hours"] == 2
        glass = await ask(bob, "Admin on prod-k8s-cluster now to stop a live outage", break_glass=True)
        assert glass["status"] == "ACTIVE" and glass["break_glass"], glass

        m = await token(maya)
        status, tasks = await api("GET", "/approvals", m)
        assert sorted(t["kind"] for t in tasks) == ["approval", "break_glass_review"], tasks
        status, body = await api("POST", f"/requests/{pending['request_id']}/approve", m, {"comment": "ok for rollback"})
        assert status == 200 and body["status"] == "ACTIVE", body

        # The demo clock: three hours on, the sweep has revoked both 1-2h grants but not
        # Alice's 4h one, and the old tokens have expired, so the page signs in again.
        before = bridge.now()
        bridge.advance(3)
        assert bridge.now() > before
        status, _ = await api("GET", "/me", m)
        assert status == 401
        g = await token(grace)
        status, grants = await api("GET", "/active-grants", g)
        assert [x["resource"] for x in grants] == ["prod-db"], grants

        status, v = await api("GET", "/audit-logs/verify", g)
        assert v["valid"], v
        edited = bridge.tamper()
        status, v = await api("GET", "/audit-logs/verify", g)
        assert not v["valid"] and v["first_invalid_id"] == edited, v

        bridge.reset()
        status, grants = await api("GET", "/active-grants", await token(grace))
        assert grants == []
        clock_drift = datetime.fromisoformat(bridge.now()) - datetime.fromisoformat(before)
        assert clock_drift < timedelta(minutes=5), clock_drift  # back on the real clock
        print("ok")

    asyncio.run(main())
    """
)


def test_demo_bridge_runs_the_app_end_to_end(tmp_path):
    env = {**os.environ, "AEGIS_DATABASE_URL": f"sqlite:///{tmp_path}/demo.db", "PYTHONPATH": str(ROOT)}
    for key in ("AEGIS_LLM_MODE", "AEGIS_SCHEDULER_ENABLED", "AEGIS_AUDIT_KEY", "AEGIS_AUTH_MODE"):
        env.pop(key, None)
    result = subprocess.run(
        [sys.executable, "-c", f"ROOT = {str(ROOT)!r}\n" + SCENARIO],
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-3000:]
    assert result.stdout.strip().endswith("ok")
