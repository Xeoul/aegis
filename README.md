# aegis-jit

A Just-In-Time IAM policy engine. Users ask for temporary access in plain English. Claude
turns each request into a structured ABAC policy, an attribute-based evaluator decides
ALLOW or DENY, and a background scheduler revokes grants when they expire.

Built with FastAPI, SQLite (SQLAlchemy 2), Pydantic v2 and APScheduler.

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
python seed_data.py --reset           # creates aegis_jit.db with mock users and resources
uvicorn app.main:app --reload         # interactive docs at http://localhost:8000/docs
```

Every endpoint except `/health` and `/auth/dev-token` requires a bearer token. In dev
mode Aegis acts as its own identity provider:

```bash
token() { curl -s localhost:8000/auth/dev-token -H 'content-type: application/json' \
  -d "{\"email\": \"$1\"}" | python -c 'import sys,json;print(json.load(sys.stdin)["access_token"])'; }
BOB=$(token bob.martinez@aegis.example)      # Engineering SRE
FRANK=$(token frank.lee@aegis.example)       # Marketing intern
GRACE=$(token grace.kim@aegis.example)       # Compliance auditor

# ALLOW: SRE, restricted resource, duration capped at 2h
curl -s localhost:8000/request-access -H "Authorization: Bearer $BOB" -H 'content-type: application/json' \
  -d '{"request_text": "Need admin on prod-k8s-cluster for 6 hours to roll back a bad deploy"}'

# DENY: intern asking for a Finance-owned confidential system
curl -s localhost:8000/request-access -H "Authorization: Bearer $FRANK" -H 'content-type: application/json' \
  -d '{"request_text": "let me edit payroll-system for a day"}'

curl -s localhost:8000/active-grants -H "Authorization: Bearer $BOB"
curl -s localhost:8000/audit-logs/verify -H "Authorization: Bearer $GRACE"
```

## Endpoints

| Method | Path | Who | Purpose |
|---|---|---|---|
| `POST` | `/auth/dev-token` | anyone (dev mode only) | Issue a token for a provisioned user |
| `GET` | `/me` | authenticated | The caller's identity |
| `POST` | `/users` | admin | Provision a user |
| `GET` | `/users`, `/resources` | authenticated | Directory and resource catalog |
| `PATCH` | `/users/{id}` | admin (not on self) | Mover/leaver changes; revokes the user's open access |
| `POST` | `/request-access` | authenticated | Submit `{request_text, break_glass?}` as the caller; returns the parsed policy, decision and reasons |
| `GET` | `/requests`, `/requests/{id}` | requester, eligible approvers, oversight | Full lifecycle of a request |
| `GET` | `/approvals` | authenticated | Requests you may approve and break-glass grants you must review |
| `POST` | `/requests/{id}/approve`, `/reject` | eligible approver | Decide a pending request (`{comment}`) |
| `POST` | `/requests/{id}/review` | eligible approver | Post-incident review of a break-glass grant |
| `POST` | `/grants/{id}/revoke` | grantee, eligible approver, security | End a grant early (`{reason}`) |
| `GET` | `/active-grants` | authenticated | Your unexpired grants (oversight roles see all, `?user_id=`) |
| `GET` | `/audit-logs` | auditor, security engineer, admin | Hash-chained history, newest first (`?user_id=`, `?event=`, `?limit=`) |
| `GET` | `/audit-logs/verify` | auditor, security engineer, admin | Recompute the chain and report the first tampered entry |

All timestamps are UTC.

## Authentication and authorization

- **Identity comes only from the token.** Tokens are matched to users by the `email` claim;
  unknown or deactivated identities get 403.
- **`AEGIS_AUTH_MODE=dev`** (default): Aegis signs HS256 tokens itself via `/auth/dev-token`.
  This lets anyone log in as any provisioned user and exists only for local testing.
- **`AEGIS_AUTH_MODE=oidc`**: tokens come from an external IdP (Keycloak, Okta, Entra ID,
  Auth0) and are verified against its JWKS (`RS256`/`ES256` only, with issuer, audience and
  expiry checks). The dev token endpoint returns 404.
- **Least privilege for administrators.** `is_admin` lets a user provision identities and read
  the audit trail. It grants no access to resources; admins go through the same request flow.

## Grant lifecycle

```
                    policy DENY ─────────────────────────────► DENIED
submit ─► evaluate ─┤ ALLOW, low risk ──────────────────────────► ACTIVE ─► REVOKED
                    │ ALLOW, restricted or delete/admin ─► PENDING_APPROVAL ─┬─ approve ─► ACTIVE
                    │                                                        ├─ reject ──► REJECTED
                    │                                                        └─ 24h ─────► EXPIRED
                    └ ALLOW + break_glass ─► ACTIVE (1h max, needs review afterwards)
```

- **Approval.** Restricted resources and `delete`/`admin` actions need a second person. The
  policy is evaluated again when the approver acts, in case the requester's attributes
  changed in the meantime.
- **Who can approve (separation of duties).** Never the requester. Allowed approvers are the
  requester's manager, a `manager` in the department that owns the resource, or a
  `security engineer`. Identity admins and auditors can't approve: provisioning, approving and
  auditing are kept apart.
- **Break-glass.** Emergency access skips approval but still has to pass the policy. It is
  capped at 1 hour and stays in the approvers' queue until someone reviews it.
- **Revocation.** Grants end when they expire (checked every minute), when revoked early, or
  on a joiner/mover/leaver change. Deactivating a user revokes their grants and cancels their
  pending requests. Changing their department, role, manager or admin flag does the same.
  Admins cannot edit their own account.

## Tamper-evident audit trail

Every audit entry stores `prev_hash` and `hash = HMAC-SHA256(AEGIS_AUDIT_KEY, prev_hash ||
entry)`. Editing, deleting or reordering a row breaks the chain from that point on, and
`GET /audit-logs/verify` reports the first bad entry. Because the key lives outside the database,
someone with only database access cannot rebuild a valid chain. A UNIQUE constraint on
`prev_hash` stops concurrent writers from forking it.

## Layout

```
app/
  config.py      Settings from environment variables
  auth.py        JWT verification (dev issuer or OIDC/JWKS), role checks
  audit.py       HMAC hash-chained audit writer and verifier
  workflow.py    Approver eligibility, activation, break-glass, revocation, leaver/mover handling
  routers/       HTTP endpoints: auth, users, access, approvals, audit
  database.py    SQLite engine, session factory, get_db dependency
  models.py      User, Resource, AccessRequest, AuditLog
  schemas.py     Pydantic I/O models: AccessRequestIn, ParsedPolicy, ABACPolicy, ...
  llm_parser.py  Natural language -> ParsedPolicy (Claude with structured outputs, or heuristic)
  evaluator.py   Builds Cedar entities, runs the policy engine, explains the decision
  scheduler.py   APScheduler sweep: expired grants -> REVOKED, stale approvals -> EXPIRED
  main.py        FastAPI app, lifespan (starts and stops the scheduler), router wiring
policies/        Cedar schema, policies and role attributes
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

## Policy as code (Cedar)

Access rules are written in [Cedar](https://www.cedarpolicy.com/), the policy language behind
AWS Verified Permissions. They are not hard-coded in Python.

| File | Contents |
|---|---|
| `policies/aegis.cedarschema` | Entity model: `User`, `Role`, `Resource`, the `read`/`write`/`delete`/`admin` actions, and the request context |
| `policies/aegis.cedar` | The rules |
| `policies/attributes.json` | Role attributes (clearance, privileged, cross-department) and the maximum duration for each sensitivity level |

The policies are checked against the schema at startup. If they fail, Aegis refuses to start.
One baseline `permit` lets active employees request catalog resources, and a set of `forbid`
guardrails constrain it. A matching `forbid` always overrides a `permit`, so each guardrail
stands on its own, and every one that fires is returned as a reason, e.g.
`[clearance] The requester's role is not cleared ...`.

| Guardrail | Rule |
|---|---|
| `clearance` | The role's clearance must cover the resource's sensitivity (1 public … 4 restricted) |
| `privileged-actions` | `delete` and `admin` need a privileged role (`sre`, `security engineer`, `admin`) |
| `department-boundary` | Confidential and restricted resources stay inside their owning department, except for cross-department roles (`auditor`, `security engineer`, `admin`) |
| `justification-required` | Restricted resources need a stated reason |
| `approval-required` | Restricted resources and privileged actions are refused until `context.approved` is true. If this is the only guardrail that fires, the request goes to `PENDING_APPROVAL`. It is evaluated again with `approved=true` when a second person approves |

Unknown roles get the lowest clearance, inactive users match no `permit`, and evaluation
errors deny. Granted durations are capped by sensitivity: 72h public, 24h internal,
8h confidential, 2h restricted.

## Prompt-injection defenses

The LLM only turns text into fields. It never decides.

1. **Delimited input.** The request text is sanitized (control characters removed, `<` and
   `>` escaped) and placed inside `<access_request>` tags. The system prompt treats it as data.
2. **Constrained output.** Structured outputs force the schema. The resource is snapped to the
   catalog (anything else becomes `unknown` and is denied), duration and free text are bounded,
   and `action` is an enum.
3. **Policy decides.** Cedar evaluates the parsed fields against the *real* user and resource
   attributes from the database. The LLM cannot influence those.
4. **Manipulation flagging.** Phrases like "ignore previous instructions", "you are now…",
   "pre-approved" or "skip the approval", fake tags and forged JSON fields set `risk_flags`.
   A flagged request is never granted automatically, even if policy allows it, and cannot use
   break-glass. It goes to a human approver.

`tests/test_prompt_injection.py` simulates a fully hijacked LLM that returns attacker-chosen
fields and checks that policy still holds.

## Configuration

| Variable | Default |
|---|---|
| `AEGIS_DATABASE_URL` | `sqlite:///./aegis_jit.db` |
| `AEGIS_LLM_MODE` | `auto` |
| `AEGIS_LLM_MODEL` | `claude-opus-5-5` |
| `AEGIS_SCHEDULER_ENABLED` | `true` |
| `AEGIS_REVOCATION_INTERVAL_SECONDS` | `60` |
| `AEGIS_AUTH_MODE` | `dev` (`oidc` for an external IdP) |
| `AEGIS_JWT_SECRET` | random per process (dev mode signing key) |
| `AEGIS_TOKEN_TTL_MINUTES` | `60` |
| `AEGIS_OIDC_ISSUER`, `AEGIS_OIDC_AUDIENCE`, `AEGIS_OIDC_JWKS_URL` | required in `oidc` mode (audience defaults to `aegis-jit`) |
| `AEGIS_AUDIT_KEY` | insecure dev key, with a warning. **Set this in any real deployment.** |

## Tests

```bash
pytest
```
