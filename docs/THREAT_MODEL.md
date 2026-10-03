# Threat model

A STRIDE analysis of Aegis-JIT: what it protects, where the trust boundaries are, how each
threat is mitigated, and what is *not* mitigated.

## Assets

| Asset | Why it matters |
|---|---|
| Grants and the AWS credentials derived from them | Direct access to production data and infrastructure |
| Policy (Cedar files, role attributes) | Whoever controls it decides who gets access |
| Identity data (users, roles, departments, managers) | Policy decisions and approver eligibility are based on it |
| Audit trail | Evidence for investigations and compliance |
| Signing keys (`AEGIS_JWT_SECRET`, `AEGIS_AUDIT_KEY`) and Aegis's own AWS principal | Compromising them undermines authentication, audit integrity or every brokered role |

## Trust boundaries

```
 Browser / API client ──(1)── Aegis API ──(2)── LLM provider (Anthropic)
                                  │
                                  ├──(3)── SQLite database
                                  ├──(4)── AWS STS / IAM
                                  └──(5)── SIEM (log shipper)
 Identity provider ──(6)── JWKS ──┤
                  └──(7)── SCIM ──┘
```

1. **Client → API.** Untrusted. All input is authenticated with a bearer JWT and validated by Pydantic.
2. **API → LLM.** The request text sent out is untrusted, and so is everything that comes back.
3. **API → DB.** Trusted storage, but database administrators are a threat to the audit trail.
4. **API → AWS.** Aegis holds a powerful principal that can assume and modify the brokered roles.
5. **API → SIEM.** One-way export that keeps an independent copy of the audit trail.
6. **IdP → API.** Tokens are trusted only after signature, issuer, audience and expiry checks.
7. **IdP → SCIM.** The IdP's provisioning client holds `AEGIS_SCIM_TOKEN` and can create,
   change and deactivate users, but never make anyone an Aegis administrator.

## STRIDE

### Spoofing

| Threat | Mitigation | Evidence |
|---|---|---|
| Acting as another user by sending their `user_id` | Identity comes only from the verified token. There is no `user_id` field in requests | `test_identity_comes_from_token_not_body` |
| Forged or tampered JWT | Signature verification; `iss`, `aud`, `exp`, `iat` required | `test_rejects_invalid_tokens` |
| `alg=none` / HS-RS algorithm confusion | Algorithms are an explicit allowlist per mode (HS256 in dev, RS256/ES256 in OIDC) | `test_rejects_alg_none`, `test_oidc_mode_verifies_rs256_against_jwks` |
| A leaver keeps using a still-valid token | `is_active` is checked on every request, not just at login | `test_unprovisioned_and_deactivated_users_are_forbidden` |
| A stolen session token used for high-risk actions | Restricted access, break-glass and approvals need a second factor from the last 15 minutes (RFC 9470 step-up) | `test_restricted_request_gets_rfc_9470_challenge_then_succeeds`, `test_approver_must_step_up`, `test_mfa_goes_stale` |
| TOTP code replay or guessing | Single-use time steps, ±1 step drift only, lockout and a high-severity alert after 5 wrong codes | `test_codes_cannot_be_replayed`, `test_brute_force_locks_and_alerts_then_admin_resets` |
| An attacker with a session swapping in their own authenticator | Re-enrolling a confirmed authenticator needs a fresh MFA token | `test_replacing_an_authenticator_needs_the_current_one` |
| Calling SCIM as a user, or without the IdP's token | SCIM accepts only `AEGIS_SCIM_TOKEN` (constant-time compare); user JWTs are refused, and SCIM is off when the variable is unset | `test_rejects_missing_or_wrong_token`, `test_disabled_without_a_token` |
| Authorization code interception in the browser login | Public client with PKCE (S256), `state` checked, exact redirect URIs registered at the IdP | `scripts/oidc_e2e.py` (CI `oidc` job) |
| Dev token endpoint used in production | Only enabled when `AEGIS_AUTH_MODE=dev`, with a warning at startup. In OIDC mode it returns 404 | `test_dev_token_disabled_in_oidc_mode` |

### Tampering

| Threat | Mitigation | Evidence |
|---|---|---|
| Editing, deleting or reordering audit rows | HMAC-SHA256 hash chain keyed outside the DB. `/audit-logs/verify` reports the first broken link | `test_detects_edited_entry`, `test_detects_deleted_entry` |
| Two writers forking the chain | UNIQUE `prev_hash`, plus an in-process lock | `app/audit.py` |
| LLM output steering the decision | Output is schema-constrained, the resource snapped to the catalog, duration bounded. Cedar decides using attributes from the DB | `test_hijacked_llm_cannot_grant_beyond_policy` |
| Policy files edited into an invalid state | Schema validation at startup; Aegis fails closed and won't start | `test_policies_validate_against_schema`, CI `security` job |
| Request text breaking out of the prompt delimiters | Control characters stripped, `<`/`>` escaped | `test_request_text_cannot_break_out_of_prompt_tags` |

### Repudiation

| Threat | Mitigation |
|---|---|
| "I never approved that" | Every approval, rejection, revocation and review is logged with its `actor_id` and a required comment |
| "That AWS call wasn't me" | STS `SourceIdentity` is the user's email, and the session name and tags identify the request. The issued access key id is in the audit trail, so CloudTrail can be joined back to it |
| Actions taken as the system | Scheduler events have `actor_id = null` and a reason (expiry, stale approval) |

### Information disclosure

| Threat | Mitigation |
|---|---|
| Users browsing other people's grants and requests | Non-oversight users see only their own. Requests they aren't involved in return 404, not 403 |
| AWS secrets leaking | Credentials are returned once with `Cache-Control: no-store` and never stored. Only the access key id is logged |
| Audit log exposure | Only auditors, security engineers and admins can read or export it |
| XSS stealing the session token | The dashboard renders with `textContent` only, under a CSP of `script-src 'self'` with no inline script, `frame-ancestors 'none'` and `nosniff`. The token is kept in `sessionStorage` |
| Request text sent to a third party | This is inherent to LLM parsing. `AEGIS_LLM_MODE=heuristic` keeps everything local |

### Denial of service

| Threat | Mitigation |
|---|---|
| Flooding requests or approvals | Pending requests expire after 24h, and the `repeated-denials` rule flags probing. **There is no rate limiting**; that belongs in a gateway in front of Aegis |
| LLM outage | In `auto` mode Aegis falls back to the heuristic parser; `anthropic` mode returns 502 |
| Revocation lost when AWS is down | The local revoke still happens, and a `CLOUD_REVOCATION_FAILED` event says manual action is needed |

### Elevation of privilege

| Threat | Mitigation | Evidence |
|---|---|---|
| Self-approval | The requester is never an eligible approver, not even a security engineer | `test_self_approval_blocked_even_for_approver_roles` |
| An identity admin granting themselves access | Admins have no resource privileges and aren't approvers, and they can't edit their own account | `test_mover_access_is_revoked_and_admin_cannot_self_modify` |
| Attributes changing between request and approval | The policy is re-evaluated when the approver acts | `test_policy_is_rechecked_at_approval_time` |
| Mover keeps their old access | Changing department, role, manager or admin flag revokes open grants | `test_mover_access_is_revoked_and_admin_cannot_self_modify` |
| A compromised IdP integration creating an administrator | SCIM ignores `is_admin`; an unknown or missing title gets the lowest clearance | `test_joiner_is_provisioned_and_can_request_access`, `test_joiner_defaults_fail_closed` |
| Break-glass used as a bypass | Policy still applies. Capped at 1h, raises a high-severity alert, needs review, and is disabled for flagged requests | `test_break_glass_does_not_bypass_policy` |
| Credentials broader than the grant | The session policy allows only the action's IAM actions on one ARN, intersected with the role's policy | `test_issue_scoped_credentials` |
| Credentials outliving the grant | Session duration is at most the grant's remaining time, and none are issued with under 15 minutes left | `test_session_never_outlives_grant` |
| A security engineer burying an alert about themselves | Nobody can resolve an alert that names them | `test_cannot_resolve_alert_about_yourself` |

## Known limitations

Being explicit about these matters as much as the mitigations above.

- **Truncating the end of the audit log isn't detected by the chain alone.** Deleting the
  newest N rows leaves a valid, shorter chain. The mitigation is the independent SIEM copy
  (the push stream or `metadata.uid`) and anchoring the head hash elsewhere. A production
  deployment should also use an append-only store (for example S3 Object Lock).
- **Compromising `AEGIS_AUDIT_KEY` allows the chain to be forged.** Keep it in a secrets
  manager or KMS, away from the database.
- **Aegis's AWS principal is highly privileged.** It needs `sts:AssumeRole` and
  `iam:PutRolePolicy` on the brokered roles. Scope it to a role-name prefix
  (`arn:aws:iam::*:role/aegis-jit-*`) with a permission boundary, and alert on its use.
- **The dashboard keeps its access token in `sessionStorage`**, which script running in the
  page could read. The strict CSP (`script-src 'self'`, no inline script) is the
  mitigation; a backend-for-frontend with an HttpOnly cookie would remove the exposure.
- **JWTs can't be revoked individually.** Short TTLs and the per-request `is_active` check
  limit the exposure. A leaked token for an active user is valid until it expires.
- **The SCIM token is a static shared secret.** Anyone holding it can deactivate users (a
  denial of service) or provision new low-clearance ones. Store it only in the IdP, rotate
  it, and restrict `/scim/v2` to the IdP's egress IPs at the gateway.
- **Injection detection is heuristic.** It is defense in depth, not the security boundary.
  The boundary is that the LLM never decides. A request that gets past detection still goes
  through Cedar with real attributes.
- **Approvers can collude.** Separation of duties stops self-approval, not a manager signing
  off for a report. The access review and alerts help find this after the fact.
- **SQLite and a single process.** The chain lock is process-local (the UNIQUE constraint
  still prevents forks across processes). Scaling out means Postgres with the chain append
  in a serializable transaction.
- **No rate limiting.** It belongs at the gateway; the TOTP lockout covers the one
  brute-forceable endpoint.
- **TOTP secrets are stored in the database unencrypted** (dev mode only; in OIDC mode the
  IdP holds the factor). A production build would encrypt them with a KMS key, or rely on the
  IdP's MFA entirely. TOTP is also phishable in real time; phishing-resistant factors
  (WebAuthn passkeys, `amr: hwk`) are accepted from the IdP.
