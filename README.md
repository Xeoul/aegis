# aegis-jit

A Just-In-Time IAM policy engine. Users ask for temporary access in plain English. Claude
turns each request into a structured ABAC policy, an attribute-based evaluator decides
ALLOW or DENY, and a background scheduler revokes grants when they expire.

Built with FastAPI, SQLite (SQLAlchemy 2), Pydantic v2 and APScheduler.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python seed_data.py                   # creates aegis_jit.db with mock users and resources
uvicorn app.main:app --reload         # interactive docs at http://localhost:8000/docs
```

Try it:

```bash
# ALLOW: SRE, restricted resource, duration capped at 2h
curl -s localhost:8000/request-access -H 'content-type: application/json' \
  -d '{"user_id": 2, "request_text": "Need admin on prod-k8s-cluster for 6 hours to roll back a bad deploy"}'

# DENY: intern asking for a Finance-owned confidential system
curl -s localhost:8000/request-access -H 'content-type: application/json' \
  -d '{"user_id": 6, "request_text": "let me edit payroll-system for a day"}'

curl -s localhost:8000/active-grants
curl -s 'localhost:8000/audit-logs?limit=20'
```

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/users` | Create a test user (`name`, `department`, `role`) |
| `GET` | `/users`, `/resources` | List seeded users and the resource catalog |
| `POST` | `/request-access` | Submit `{user_id, request_text}`; returns the parsed policy, the ABAC decision and its reasons |
| `GET` | `/active-grants` | Unexpired `ACTIVE` grants (optional `?user_id=`) |
| `GET` | `/audit-logs` | Every submission, grant, denial and revocation, newest first (`?user_id=`, `?event=`, `?limit=`) |

All timestamps are UTC.

## Layout

```
app/
  database.py    SQLite engine, session factory, get_db dependency
  models.py      User, Resource, AccessRequest, AuditLog
  schemas.py     Pydantic I/O models: AccessRequestIn, ParsedPolicy, ABACPolicy, ...
  llm_parser.py  Natural language -> ParsedPolicy (Claude with structured outputs, or heuristic)
  evaluator.py   ABAC rules -> ALLOW / DENY with reasons
  scheduler.py   APScheduler job: ACTIVE grants past expires_at -> REVOKED
  main.py        FastAPI app and lifespan (starts and stops the scheduler)
seed_data.py     Mock users and resources (idempotent; --reset to wipe)
tests/           pytest suite (runs offline)
```

## Request parsing

`llm_parser.py` sends the request text and the resource catalog to Claude (`claude-opus-5-5`)
with a system prompt. It uses structured outputs, so the reply always validates against
`ParsedPolicy` (`resource`, `action`, `allow_reason`, `duration_hours`). Resource names are
matched back to the catalog, and anything else becomes `unknown`, which is denied. If a safety
classifier declines a request, the server-side `fallbacks: "default"` option retries it on
another model.

| `AEGIS_LLM_MODE` | Behaviour |
|---|---|
| `auto` (default) | Use Claude when `ANTHROPIC_API_KEY` or `ANTHROPIC_AUTH_TOKEN` is set, otherwise use the keyword heuristic parser. If the API call fails, fall back to the heuristic. |
| `anthropic` | Claude only; if parsing fails the endpoint returns 502 |
| `heuristic` | Offline keyword parser only |

Every response and audit entry records which parser ran.

## Policy rules (`evaluator.py`)

A request is allowed only if every rule passes. Each rule that fails adds a reason to the response.

1. **Catalog**: the resource must exist.
2. **Clearance**: the role must be cleared for the resource's sensitivity
   (`intern` → public, `analyst`/`contractor` → internal,
   `engineer`/`manager`/`auditor` → confidential, `sre`/`senior engineer`/`security engineer`/`admin` → restricted).
3. **Privileged actions**: `delete` and `admin` require `sre`, `security engineer` or `admin`.
4. **Department boundary**: confidential and restricted resources that have an `owner_department`
   are only granted to that department, except to `security engineer`, `auditor` and `admin`.
5. **Justification**: restricted resources require a stated reason.

Granted durations are capped per sensitivity level: 72h public, 24h internal, 8h confidential,
2h restricted.

## Configuration

| Variable | Default |
|---|---|
| `AEGIS_DATABASE_URL` | `sqlite:///./aegis_jit.db` |
| `AEGIS_LLM_MODE` | `auto` |
| `AEGIS_LLM_MODEL` | `claude-opus-5-5` |
| `AEGIS_SCHEDULER_ENABLED` | `true` |
| `AEGIS_REVOCATION_INTERVAL_SECONDS` | `60` |

## Tests

```bash
pytest
```
