# Aegis-JIT design reference

How each part of the system works. For the overview, see the [README](../README.md); for the security analysis, see the [threat model](THREAT_MODEL.md).

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
| `POST` | `/grants/{id}/credentials` | grantee only | Exchange an active grant for scoped, temporary AWS credentials |
| `GET` | `/active-grants` | authenticated | Your unexpired grants (oversight roles see all, `?user_id=`) |
| `GET` | `/audit-logs` | auditor, security engineer, admin | Hash-chained history, newest first (`?user_id=`, `?event=`, `?limit=`) |
| `GET` | `/audit-logs/verify` | auditor, security engineer, admin | Recompute the chain and report the first tampered entry |
| `GET` | `/audit-logs/export` | auditor, security engineer, admin | OCSF-style NDJSON for a SIEM (`?after_id=` cursor) |
| `GET` | `/alerts` | auditor, security engineer, admin | Detection findings (`?status=`, `?severity=`) |
| `POST` | `/alerts/{id}/resolve` | security engineer (not about themselves) | Close an alert (`{note, false_positive}`) |
| `GET` | `/reports/access-review` | auditor, security engineer, admin | User access review with control checks (`?days=`, `?format=csv`) |

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

## Real temporary AWS credentials (zero standing privilege)

Resources can be backed by AWS (`aws_service`, `aws_resource_arn`, `aws_role_arn`). With
`AEGIS_CREDENTIAL_BROKER=aws`, `POST /grants/{id}/credentials` calls `sts:AssumeRole` for the
grantee:

- **Least privilege.** A session policy allows only the IAM actions for the granted action
  (e.g. `read` on S3 gives `s3:GetObject`, `s3:ListBucket` and `s3:GetBucketLocation`) on that
  one ARN. AWS takes the intersection of the role's policy and the session policy, so the
  credentials are never broader than the grant.
- **Bounded lifetime.** The session duration is at most the grant's remaining time. If the
  grant ends within the 15-minute STS minimum, no credentials are issued.
- **Attribution.** `SourceIdentity` is the user's email, the session name is
  `aegis-<request>-<user>`, and the request id is a session tag. CloudTrail therefore shows the
  human and the approval behind every API call. The access key id (never the secret) is written
  to the Aegis audit trail.
- **Early revocation.** STS credentials cannot be recalled, so revoking a grant early (manually,
  or through a leaver/mover change) adds a `Deny` statement to the role's
  `AegisRevokedSessions` policy. It matches that grant's sessions through `aws:userid`, and the
  scheduler removes it once those sessions have expired. If AWS rejects the change, a
  `CLOUD_REVOCATION_FAILED` audit event says manual action is needed.

Try it against LocalStack:

```bash
docker compose up -d localstack
export AWS_ENDPOINT_URL=http://localhost:4566 AWS_REGION=us-east-1 AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test
python scripts/localstack_bootstrap.py          # bucket, table, secret, and the IAM roles Aegis assumes
python seed_data.py --reset
AEGIS_CREDENTIAL_BROKER=aws uvicorn app.main:app
```

## Tamper-evident audit trail

Every audit entry stores `prev_hash` and `hash = HMAC-SHA256(AEGIS_AUDIT_KEY, prev_hash ||
entry)`. Editing, deleting or reordering a row breaks the chain from that point on, and
`GET /audit-logs/verify` reports the first bad entry. Because the key lives outside the database,
someone with only database access cannot rebuild a valid chain. A UNIQUE constraint on
`prev_hash` stops concurrent writers from forking it.

## Detection and governance

**Detection rules** (`app/detection.py`) run after every request, in the same transaction.
Each rule has a one-hour cooldown per user.

| Rule | Severity | Fires when |
|---|---|---|
| `prompt-injection` | high | The request text matched manipulation patterns |
| `break-glass-used` | high | Emergency access was taken without approval |
| `privilege-escalation-attempt` | medium | A request was denied by the `clearance` or `privileged-actions` guardrail |
| `repeated-denials` | medium | 3 or more denials within an hour (possible probing) |
| `sensitive-access-burst` | medium | Requests for 5 or more different confidential/restricted resources within 24h |
| `off-hours-sensitive-access` | low | A confidential/restricted request outside business hours |

Security engineers triage alerts, marking them resolved or false positive. They cannot close
an alert about themselves, and auditors can view alerts but not close them.

**Access review.** `GET /reports/access-review` supports periodic certification, as SOX, SOC 2
and ISO 27001 require. For each user it lists active grants, resources used, denials,
break-glass use, approvals they gave, open alerts and a recommendation (`CERTIFY`,
`INVESTIGATE`, `REVOKE`, `NO ACTION`). It also reports **control checks**: self-approvals,
active grants held by deactivated users, unreviewed break-glass, and whether the audit chain is
intact. CSV export is available for spreadsheets.

**SIEM integration.** Audit events map to OCSF-style JSON (Account Change 3001, Authorize
Session 3003, Detection Finding 2004). They can be pushed as JSON lines
(`AEGIS_SIEM_LOG_FILE=/path` or `stdout`, for Splunk UF, Filebeat or Fluent Bit) or pulled from
`/audit-logs/export?after_id=N`. Each event carries its chain hash in `metadata.uid`, so the
SIEM copy can be checked against the source.

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
| `AEGIS_CREDENTIAL_BROKER` | `none` (`aws` to issue STS credentials) |
| `AEGIS_AWS_MAX_SESSION_SECONDS` | `3600` (must not exceed the roles' `MaxSessionDuration`) |
| `AEGIS_AWS_ACCOUNT_ID` | `000000000000` (LocalStack), used by `seed_data.py` to build ARNs |
| `AEGIS_SIEM_LOG_FILE` | unset (a file path, or `stdout`) |
| `AEGIS_BUSINESS_HOURS_UTC`, `AEGIS_BUSINESS_DAYS` | `07-19`, `0-4` (Mon–Fri) for the off-hours rule |
| `AEGIS_DEMO_MODE` | `false` (`true`: sandbox banner, and data reset every `AEGIS_DEMO_RESET_MINUTES`, default 180) |
| `AEGIS_AUDIT_KEY` | insecure dev key, with a warning. **Set this in any real deployment.** |

## Live demo

`demo/` publishes the app to GitHub Pages as a single page that runs the real API in the
browser: [Pyodide](https://pyodide.org) (Python compiled to WebAssembly) loads `app/` and
`seed_data.py`, and the page calls the endpoints through `demo/bridge.py`, which hands each
request straight to the FastAPI app. Tokens, the policy engine, approvals, grants and the
audit chain all go through the same code as the server.

For the browser, `bridge.py` changes a few things:

- **Parsing:** requests use the heuristic parser. A public page can't hold an API key.
- **Threads:** endpoints run inline on the event loop, not in a thread pool.
- **Scheduler:** the page runs the scheduler's sweep every minute itself; APScheduler isn't loaded.
- **Policy engine:** `cedarpy` is a native extension, so the page loads Cedar's official
  WebAssembly build (`@cedar-policy/cedar-wasm`, the same Cedar version). A small stand-in in
  `bridge.py` forwards the evaluator's four calls to it, so the policies, schema and decisions
  are the real ones. `build.sh` vendors the build, pinned and checked against npm's integrity hash.
- **Demo clock:** a clock you can skip forward, so expiry can be shown without waiting.
- **Tampering:** a button that edits an audit row directly in SQLite, so the chain check has something to catch.

Everything lives in a SQLite file in the page's memory and resets on reload.

```bash
demo/build.sh                       # builds _site/: the page, the source it runs, the wheels it installs
python -m http.server -d _site      # then open http://localhost:8000
```

`.github/workflows/pages.yml` runs the tests, builds `_site`, smoke-tests it and publishes it
to the `gh-pages` branch on every push to `main`. `tests/test_demo_bridge.py` walks the demo's
flows through the bridge under CPython. `demo/smoke.mjs` boots the built site under Node with
Pyodide and cedar-wasm, and checks that the in-browser engine reaches the same decisions as the
server; CI runs it on every pull request.
