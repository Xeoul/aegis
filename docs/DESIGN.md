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
| `POST` | `/auth/mfa/enroll`, `/auth/step-up` | authenticated (dev mode only) | TOTP enrollment and step-up; see [MFA step-up](#mfa-step-up) |
| `POST` | `/users/{id}/mfa/reset` | admin (not on self) | Reset a lost or locked authenticator |
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
| `GET` `POST` | `/audit-logs/checkpoints` | auditor, security engineer, admin | Signed checkpoints and the public key to check them; `POST` signs one now |
| `GET` | `/audit-logs/export` | auditor, security engineer, admin | OCSF-style NDJSON for a SIEM (`?after_id=` cursor) |
| `GET` | `/alerts` | auditor, security engineer, admin | Detection findings (`?status=`, `?severity=`) |
| `POST` | `/alerts/{id}/resolve` | security engineer (not about themselves) | Close an alert (`{note, false_positive}`) |
| `POST` | `/policy/simulate` | auditor, security engineer, admin | What-if decision with optional role, department, sensitivity, MFA and approval overrides; nothing is granted |
| `GET` | `/policy/tests` | auditor, security engineer, admin | Run `policies/tests.json` against the loaded policies |
| `POST` | `/certifications` | auditor, security engineer, admin | Start a recertification of every active grant (`{name, due_in_hours}`) |
| `GET` | `/certifications`, `/certifications/{id}` | auditor, security engineer, admin | Campaigns with certified / revoked / pending / ended counts |
| `POST` | `/certifications/items/{id}/certify`, `/revoke` | eligible reviewer (never the holder) | Confirm or end one grant (`{comment}`); open items also appear in `/approvals` |
| `GET` | `/reports/access-review` | auditor, security engineer, admin | User access review with control checks (`?days=`, `?format=csv`) |
| `GET` `POST` `PUT` `PATCH` `DELETE` | `/scim/v2/Users[/{id}]` | identity provider (SCIM token) | Joiner/mover/leaver provisioning; see [SCIM provisioning](#scim-provisioning) |
| `GET` | `/scim/v2/ServiceProviderConfig`, `/ResourceTypes`, `/Schemas` | identity provider (SCIM token) | SCIM discovery |

All timestamps are UTC.

## Authentication and authorization

- **Identity comes only from the token.** Tokens are matched to users by the `email` claim;
  unknown or deactivated identities get 403.
- **`AEGIS_AUTH_MODE=dev`** (default): Aegis signs HS256 tokens itself via `/auth/dev-token`.
  This lets anyone log in as any provisioned user and exists only for local testing.
- **`AEGIS_AUTH_MODE=oidc`**: tokens come from an external IdP (Keycloak, Okta, Entra ID,
  Auth0) and are verified against its JWKS (`RS256`/`ES256` only, with issuer, audience and
  expiry checks). The dev token endpoint returns 404.
- **Dashboard sign-in in `oidc` mode** uses the authorization code flow with PKCE (S256) as a
  public client (`AEGIS_OIDC_CLIENT_ID`, default `aegis-jit`), with `state` and `nonce`
  checks. `/meta` publishes the issuer and client id, and the dashboard's CSP allows
  `connect-src` to the issuer's origin only. A step-up challenge sends the person back to the
  IdP with `prompt=login&max_age=0`.
- **A real IdP, tested in CI.** [`deploy/keycloak/aegis-realm.json`](../deploy/keycloak/aegis-realm.json)
  is a Keycloak realm with the demo people, the PKCE client, an audience mapper (`aud:
  aegis-jit`), and a browser flow that asks for a password and a TOTP code and reports them
  as `amr: ["pwd", "otp"]`. The `oidc` CI job starts Keycloak, signs in to the dashboard in a
  headless browser and checks what Aegis does with the token
  ([`scripts/oidc_e2e.py`](../scripts/oidc_e2e.py)).
- **Least privilege for administrators.** `is_admin` lets a user provision identities and read
  the audit trail. It grants no access to resources; admins go through the same request flow.

## MFA step-up

A valid session isn't enough for the riskiest actions, since session tokens get stolen
(infostealers, AiTM phishing). Three actions need a **recent second factor**: requesting a
restricted resource, using break-glass, and approving anyone's access. This is OAuth step-up
authentication ([RFC 9470](https://www.rfc-editor.org/rfc/rfc9470)):

```
POST /request-access            (token without a recent MFA)
401 WWW-Authenticate: Bearer error="insufficient_user_authentication",
    error_description="...", acr_values="urn:aegis:acr:mfa", max_age=900
```

The client re-authenticates with MFA and retries. Nothing is recorded as a request, but a
`STEP_UP_REQUIRED` audit entry is. For requests the decision stays in Cedar
(`context.mfa` and the `mfa-required` guardrail); a request that other guardrails deny is
simply denied, so a step-up never hints that a denied request would otherwise succeed. The
requester's MFA state is stored with the request and reused when the policy is re-checked
at approval time.

Where the second factor comes from ([`mfa.py`](../app/mfa.py)):

- **OIDC mode:** the IdP does MFA. A token counts when its `amr` claim
  ([RFC 8176](https://www.rfc-editor.org/rfc/rfc8176)) names a second factor (`mfa`, `otp`,
  `hwk`, `swk`, `fido`, ...) or its `acr` is listed in `AEGIS_OIDC_MFA_ACR`, and `auth_time`
  is within `AEGIS_MFA_MAX_AGE_MINUTES` (default 15).
- **Dev mode:** the stand-in issuer has its own TOTP authenticator
  ([RFC 6238](https://www.rfc-editor.org/rfc/rfc6238), checked against the RFC's test vectors).
  `POST /auth/mfa/enroll` returns a secret and `otpauth://` URI; `POST /auth/step-up {code}`
  verifies a code and issues a token with `amr`, `acr` and `auth_time`, like an IdP would.

TOTP protections: codes are single use (the last accepted time step is stored, so a replayed
code fails even within its 30 seconds), ±1 step of clock drift, constant-time comparison,
five wrong codes in a row lock the authenticator and raise a high-severity `mfa-brute-force`
alert, and replacing a confirmed authenticator needs a fresh MFA token. An administrator
resets a lost or locked authenticator with `POST /users/{id}/mfa/reset`, never their own.

## SCIM provisioning

In a real company, people join, move and leave in the identity provider (Okta, Entra ID), not
in each application. Aegis implements the SCIM 2.0 server side
([RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) / [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644))
at `/scim/v2`, so the IdP stays the source of truth ([`routers/scim.py`](../app/routers/scim.py)).

- **A separate credential.** The IdP authenticates with `AEGIS_SCIM_TOKEN` (a bearer token
  compared in constant time), not with a person's token. With the variable unset, SCIM is off
  and every route returns 404.
- **One lifecycle.** SCIM and `PATCH /users/{id}` both call
  [`identity.apply_changes`](../app/identity.py). Setting `active: false` (Okta's
  `{"op": "replace", "value": {"active": false}}` or Entra ID's
  `{"op": "Replace", "path": "active", "value": "False"}`) revokes every grant, cancels
  pending requests and denies live AWS sessions. Changing `title` (role), department or
  manager is a mover event and revokes open access. A rename is not.
- **Attribute mapping.** `userName` is the work email that tokens are matched on, `title` is
  the Aegis role, and the enterprise extension carries `department` and `manager.value` (the
  manager's SCIM id). `externalId` stores the IdP's own id. A missing title or department
  falls back to `employee` / `Unassigned`, which gets the lowest clearance (fail closed).
- **No admin over SCIM.** `is_admin` can't be set through SCIM; making someone an identity
  administrator stays a deliberate action by an existing one.
- **History is kept.** `DELETE` deactivates instead of erasing, so the audit trail still
  resolves who did what. Changes are audited with no actor and the detail "via SCIM".
- **Scope.** Users only (no Groups: Aegis decides on attributes, not group membership), and
  equality filters on `userName`, `externalId` and `id`, which is what IdPs use to match
  accounts before creating them. Attributes Aegis doesn't store are accepted and ignored.

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
| `mfa-required` | Restricted resources and break-glass need `context.mfa`: a second factor within the last 15 minutes. If this (with or without `approval-required`) is all that fires, the API answers with a step-up challenge instead of a denial; see [MFA step-up](#mfa-step-up) |
| `approval-required` | Restricted resources and privileged actions are refused until `context.approved` is true. If this is the only guardrail that fires, the request goes to `PENDING_APPROVAL`. It is evaluated again with `approved=true` when a second person approves |

**Policy tests.** [`policies/tests.json`](../policies/tests.json) pins what each guardrail
must decide: a request (role, department, resource sensitivity and owner, action, context)
and its outcome (`allow`, `needs-approval`, `step-up` or `deny`, and which policies decide it).
A policy change and the cases it affects are reviewed together. CI runs the suite
(`python -m app.policy_tests`) against the server's Cedar, and the demo smoke test runs it
again against Cedar's WebAssembly build.

**What-if simulation.** `POST /policy/simulate` (auditors, security engineers and admins)
asks the same policies what they would decide for a real person and resource, optionally
changed: a different role or department (a mover), a reclassified resource, with or
without MFA, approval or break-glass. The person and resource are copied before overrides,
so nothing stored changes and nothing is granted; the question itself is audited
(`POLICY_SIMULATED`). `GET /policy/tests` runs the test suite against the loaded policies.

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

**Signed checkpoints** close the gap a chain alone leaves: deleting the *newest* entries
leaves a shorter chain that still verifies. Every `AEGIS_CHECKPOINT_INTERVAL_MINUTES`
(default 15), or on `POST /audit-logs/checkpoints`, Aegis signs "the log had N entries ending
at entry #id with hash h" with an Ed25519 key (`AEGIS_CHECKPOINT_KEY`, separate from the HMAC
key) and appends it to `AEGIS_CHECKPOINT_FILE`, outside the database. Checkpoints are linked
by hash, and `/audit-logs/verify` checks each signature, the links, and that the database
still holds what each one vouches for. So it catches truncation, removing a checkpoint, and
even an insider with the HMAC key rewriting the newest entries. `GET /audit-logs/checkpoints`
publishes the public key, so anyone can check the file independently
([`checkpoints.py`](../app/checkpoints.py)).

## Rate limiting

Token buckets per caller on the endpoints worth abusing ([`ratelimit.py`](../app/ratelimit.py)):
sign-in (30 a minute per client address), MFA codes (10 a minute per user, on top of the
five-strikes lockout), access requests (30 a minute per user; each may call the LLM) and policy
simulation (60 a minute). Over the limit the API answers `429` with `Retry-After`, and the
first refusal in a run is audited (`RATE_LIMITED`), so a flood can't flood the audit log too.
The buckets are per process and memory-bounded; with several instances, enforce the same
limits at the gateway. `AEGIS_RATE_LIMITS=false` turns them off.

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

## Access recertification

An access review report shows what people hold; a recertification makes someone answer for
it. An auditor or security engineer starts a campaign (`POST /certifications`), which
snapshots every active grant. Each one appears in the approval queue of the people who could
have approved it (the holder's manager, a manager of the owning department, or security,
never the holder), who certify it (with a comment) or revoke it. When the deadline passes,
the scheduler closes the campaign and **revokes every grant nobody certified**, so an ignored
review fails closed rather than rubber-stamping access. Grants that expired or were revoked
before review are counted as `ended`. Every step is in the audit chain
(`CERTIFICATION_STARTED`, `ACCESS_CERTIFIED`, `ACCESS_REVOKED`, `CERTIFICATION_CLOSED`).

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
| `AEGIS_OIDC_CLIENT_ID` | `aegis-jit` (the dashboard's public PKCE client at the IdP) |
| `AEGIS_CREDENTIAL_BROKER` | `none` (`aws` to issue STS credentials) |
| `AEGIS_AWS_MAX_SESSION_SECONDS` | `3600` (must not exceed the roles' `MaxSessionDuration`) |
| `AEGIS_AWS_ACCOUNT_ID` | `000000000000` (LocalStack), used by `seed_data.py` to build ARNs |
| `AEGIS_SIEM_LOG_FILE` | unset (a file path, or `stdout`) |
| `AEGIS_BUSINESS_HOURS_UTC`, `AEGIS_BUSINESS_DAYS` | `07-19`, `0-4` (Mon–Fri) for the off-hours rule |
| `AEGIS_DEMO_MODE` | `false` (`true`: sandbox banner, and data reset every `AEGIS_DEMO_RESET_MINUTES`, default 180) |
| `AEGIS_AUDIT_KEY` | insecure dev key, with a warning. **Set this in any real deployment.** |
| `AEGIS_MFA_MAX_AGE_MINUTES` | `15` (how recent a second factor must be for step-up actions) |
| `AEGIS_OIDC_MFA_ACR` | unset (comma-separated IdP `acr` values that count as MFA; `amr` values like `mfa` and `otp` always do) |
| `AEGIS_CHECKPOINT_KEY` | derived from the audit key, with a warning. Base64 Ed25519 seed (32 bytes); **set this in any real deployment** |
| `AEGIS_CHECKPOINT_FILE`, `AEGIS_CHECKPOINT_INTERVAL_MINUTES` | `./audit-checkpoints.jsonl`, `15` |
| `AEGIS_RATE_LIMITS` | `true` |
| `AEGIS_SCIM_TOKEN` | unset (SCIM disabled). Set a long random value and give it to the IdP to enable `/scim/v2` |

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
