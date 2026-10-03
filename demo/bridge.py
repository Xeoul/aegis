"""Runs the Aegis API inside a web page, for the live demo.

The page loads Python in the browser (Pyodide), writes the real ``app/`` package next to
this file, and calls :func:`call` for every API request. Requests go through the same
FastAPI app, dependencies, policy engine and audit chain as the server; there's just no
network in between. Three things are swapped for the browser:

* **Request parsing** uses Aegis's own offline keyword parser (``AEGIS_LLM_MODE=heuristic``).
  A public page can't hold an Anthropic API key, so the Claude client is never created.
* **Threads.** FastAPI runs ``def`` endpoints in a thread pool, and the browser has no
  threads, so they run inline on the event loop instead.
* **The scheduler.** APScheduler needs threads and isn't loaded; the page calls :func:`sweep`
  on a timer instead, which runs the scheduler's own job (``scheduler.run_sweep``).
* **The policy engine.** ``cedarpy`` is a native extension that can't load in the browser, so
  the page loads Cedar's official WebAssembly build (``@cedar-policy/cedar-wasm``, the same
  Cedar engine) and a small stand-in module forwards the evaluator's calls to it. The
  policies, schema and decisions are the real ones.

It also adds a demo clock (:func:`advance`) so expiry can be shown without waiting hours.
"""

import contextlib
import datetime as _dt
import io
import json
import os
import secrets
import sys
import types

# Settings are read once, on import, so these come first.
# (The database path can be overridden, for the tests.)
os.environ.setdefault("AEGIS_DATABASE_URL", "sqlite:////tmp/aegis-demo.db")
os.environ.update(
    AEGIS_LLM_MODE="heuristic",
    AEGIS_SCHEDULER_ENABLED="false",
    AEGIS_AUTH_MODE="dev",
    AEGIS_LOG_LEVEL="WARNING",
    # A fresh key per page load: the demo's audit chain is real, just short-lived.
    AEGIS_AUDIT_KEY=secrets.token_hex(32),
    # The page's "identity provider" tab provisions people over SCIM with this token.
    AEGIS_SCIM_TOKEN=secrets.token_hex(32),
)

# llm_parser imports the Anthropic SDK at the top of the module. It's never called in
# heuristic mode, so a stand-in with the two names the module refers to is enough.
if "anthropic" not in sys.modules:
    _anthropic = types.ModuleType("anthropic")

    class APIError(Exception):
        pass

    class Anthropic:
        def __init__(self, *args, **kwargs):
            raise APIError("Claude isn't available in the browser demo")

    _anthropic.APIError = APIError
    _anthropic.Anthropic = Anthropic
    sys.modules["anthropic"] = _anthropic

# app.scheduler builds an APScheduler BackgroundScheduler, which needs threads and
# multiprocessing. The page runs the same sweep on a timer instead (see sweep), so the
# scheduler is never created; this stand-in only has to satisfy the import.
if "apscheduler" not in sys.modules:
    _background = types.ModuleType("apscheduler.schedulers.background")

    class BackgroundScheduler:
        def __init__(self, *args, **kwargs):
            raise RuntimeError("The browser demo runs the sweep itself; there is no background scheduler")

    _background.BackgroundScheduler = BackgroundScheduler
    sys.modules["apscheduler"] = types.ModuleType("apscheduler")
    sys.modules["apscheduler.schedulers"] = types.ModuleType("apscheduler.schedulers")
    sys.modules["apscheduler.schedulers.background"] = _background

# The policy engine. On a server, app.evaluator uses cedarpy (Cedar's Rust core as a CPython
# extension). In the browser the page loads Cedar's own WebAssembly build and exposes it as
# ``globalThis.aegisCedar(function_name, json_argument) -> json_result``. This stand-in gives
# app.evaluator the four cedarpy functions it uses, backed by that same engine.
try:
    import cedarpy  # noqa: F401  (a real install wins, e.g. under CPython in the tests)
except ImportError:
    from types import SimpleNamespace

    def _cedar(function: str, argument):
        import js  # Pyodide's bridge to the page's JavaScript

        return json.loads(js.aegisCedar(function, json.dumps(argument)))

    def _messages(errors) -> list[str]:
        return [e.get("message", "") if "message" in e else e["error"]["message"] for e in errors]

    class _Handle:
        @staticmethod
        def from_str(text: str) -> str:
            return text  # cedar-wasm takes policy and schema text directly

    def validate_policies(policies: str, schema: str) -> SimpleNamespace:
        answer = _cedar("validate", {"schema": schema, "policies": {"staticPolicies": policies}})
        failed = answer["errors"] if answer["type"] != "success" else answer["validationErrors"]
        errors = _messages(failed)
        return SimpleNamespace(validation_passed=not errors, errors=errors)

    def policies_to_json_str(policies: str) -> str:
        # Cedar numbers policies policy0, policy1, ... in source order, both here and when it
        # authorizes, so the ids line up with the reasons isAuthorized returns.
        parts = _cedar("policySetTextToParts", policies)
        if parts["type"] != "success":
            raise ValueError(_messages(parts["errors"]))
        static = {}
        for i, text in enumerate(parts["policies"]):
            converted = _cedar("policyToJson", text)
            if converted["type"] != "success":
                raise ValueError(_messages(converted["errors"]))
            static[f"policy{i}"] = converted["json"]
        return json.dumps({"staticPolicies": static, "templates": {}, "templateLinks": []})

    def is_authorized(request: dict, policies: str, entities: list, schema=None, verbose: bool = False):
        call = {**request, "policies": {"staticPolicies": policies}, "entities": entities}
        if schema is not None:
            call["schema"] = schema
        answer = _cedar("isAuthorized", call)
        if answer["type"] != "success":
            return SimpleNamespace(
                allowed=False,
                decision="Deny",
                diagnostics=SimpleNamespace(reasons=[], errors=_messages(answer["errors"])),
            )
        response = answer["response"]
        return SimpleNamespace(
            allowed=response["decision"] == "allow",
            decision=response["decision"].capitalize(),
            diagnostics=SimpleNamespace(
                reasons=response["diagnostics"]["reason"], errors=_messages(response["diagnostics"]["errors"])
            ),
        )

    _cedarpy = types.ModuleType("cedarpy")
    _cedarpy.PolicySet = _cedarpy.Schema = _Handle
    _cedarpy.validate_policies = validate_policies
    _cedarpy.policies_to_json_str = policies_to_json_str
    _cedarpy.is_authorized = is_authorized
    sys.modules["cedarpy"] = _cedarpy

import anyio.to_thread


async def _run_inline(func, *args, **_kwargs):
    return func(*args)


anyio.to_thread.run_sync = _run_inline


class DemoDatetime(_dt.datetime):
    """``datetime`` with an adjustable offset, for the demo clock.

    Aegis reads the time through ``app.database.utcnow`` and PyJWT checks token times with
    its own ``datetime.now``; both are pointed at this class so they stay in agreement.
    Arithmetic keeps the subclass, so tokens and timestamps built from it do too.
    """

    offset = _dt.timedelta()

    @classmethod
    def now(cls, tz=None):
        t = _dt.datetime.now(tz) + cls.offset
        return cls(t.year, t.month, t.day, t.hour, t.minute, t.second, t.microsecond, t.tzinfo)


import jwt.api_jwt  # noqa: E402

from app import database  # noqa: E402

database.datetime = DemoDatetime
jwt.api_jwt.datetime = DemoDatetime

from sqlalchemy import select, text  # noqa: E402

import seed_data  # noqa: E402
from app import scheduler  # noqa: E402
from app.main import app  # noqa: E402
from app.models import User  # noqa: E402


def reset() -> None:
    """Start over: empty tables, the seeded users and resources, and the real clock."""
    DemoDatetime.offset = _dt.timedelta()
    with contextlib.redirect_stdout(io.StringIO()):  # seed() prints the tables it created
        seed_data.seed(reset=True)


def users() -> str:
    """The seeded people, for the page's sign-in picker (the API's own list needs a token)."""
    with database.SessionLocal() as db:
        rows = db.scalars(select(User).order_by(User.id)).all()
        by_id = {u.id: u for u in rows}
        return json.dumps(
            [
                dict(
                    id=u.id,
                    name=u.name,
                    email=u.email,
                    department=u.department,
                    role=u.role,
                    is_admin=u.is_admin,
                    manager=by_id[u.manager_id].name if u.manager_id in by_id else None,
                    active=u.is_active,
                )
                for u in rows
            ]
        )


async def call(method: str, path: str, token: str | None = None, body: str | None = None) -> str:
    """Send one HTTP request to the FastAPI app and return ``{"status", "body"}`` as JSON."""
    path_only, _, query = path.partition("?")
    headers = [(b"host", b"aegis.demo"), (b"content-type", b"application/json")]
    if token:
        headers.append((b"authorization", f"Bearer {token}".encode()))
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "https",
        "path": path_only,
        "raw_path": path_only.encode(),
        "query_string": query.encode(),
        "root_path": "",
        "headers": headers,
        "client": ("127.0.0.1", 0),
        "server": ("aegis.demo", 443),
    }
    request_body = (body or "").encode()
    delivered = False

    async def receive():
        nonlocal delivered
        if not delivered:
            delivered = True
            return {"type": "http.request", "body": request_body, "more_body": False}
        return {"type": "http.disconnect"}

    status = 500
    chunks: list[bytes] = []

    async def send(message):
        nonlocal status
        if message["type"] == "http.response.start":
            status = message["status"]
        elif message["type"] == "http.response.body":
            chunks.append(message.get("body", b""))

    await app(scope, receive, send)
    raw = b"".join(chunks).decode()
    try:
        payload = json.loads(raw) if raw else None
    except json.JSONDecodeError:
        payload = raw
    return json.dumps({"status": status, "body": payload})


async def scim(method: str, path: str, body: str | None = None) -> str:
    """A SCIM call as the identity provider would make it: with the provisioning token, not a user's."""
    return await call(method, path, os.environ["AEGIS_SCIM_TOKEN"], body)


def sweep() -> None:
    """What the server's scheduler does every minute: revoke expired grants, expire stale requests."""
    scheduler.run_sweep()


def advance(hours: float) -> str:
    """Move the demo clock forward, then sweep, as the scheduler would once that time had passed."""
    DemoDatetime.offset += _dt.timedelta(hours=hours)
    sweep()
    return now()


def now() -> str:
    return database.utcnow().isoformat(timespec="seconds")


def tamper() -> int | None:
    """Quietly edit one audit entry in the database, the way someone with only database access
    could, so the page can show the chain check catching it. Returns the edited entry's id."""
    with database.engine.begin() as conn:
        ids = conn.execute(text("SELECT id FROM audit_logs ORDER BY id")).scalars().all()
        if not ids:
            return None
        target = ids[len(ids) // 2]
        conn.execute(text("UPDATE audit_logs SET detail = detail || ' (edited)' WHERE id = :id"), {"id": target})
    return target


reset()
