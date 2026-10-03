# Control mapping

How Aegis-JIT's features map to common control frameworks, with the code and tests that show
each one. This is a design-level mapping for a portfolio project, not a certified assessment.

## NIST SP 800-53 Rev. 5

| Control | Requirement (summary) | How Aegis-JIT implements it | Evidence |
|---|---|---|---|
| **AC-2** Account Management | Manage accounts, including authorization and review | Admin-only provisioning with audit; SCIM 2.0 provisioning from the IdP; recertification campaigns and per-user access review | `routers/users.py`, `routers/scim.py`, `/reports/access-review` |
| **AC-2(1)** Automated System Account Management | Support account management with automated mechanisms | The IdP drives joiner/mover/leaver over SCIM, through the same lifecycle code as the admin API | `test_okta_style_deactivation_revokes_access`, `test_mover_via_patch_revokes_open_access` |
| **AC-2(2)** Automated Temporary Account Management | Automatically remove temporary access | Every grant has `expires_at`; the scheduler revokes it; STS sessions expire with it | `scheduler.py`, `test_request_access_allow_then_revoke` |
| **AC-2(3)** Disable Accounts | Disable accounts when no longer needed | `PATCH /users/{id}` with `is_active=false`, or SCIM `active: false` from the IdP, revokes grants, cancels pending requests and denies live AWS sessions | `test_leaver_loses_all_access`, `test_leaver_denies_issued_sessions`, `test_entra_style_deactivation` |
| **AC-2(4)** Automated Audit Actions | Audit account creation, modification and disabling | `USER_CREATED`, `USER_UPDATED` and `USER_DEACTIVATED` events in the chained log | `test_admin_actions_are_audited` |
| **AC-2(6)** Dynamic Privilege Management | Grant privileges dynamically | Just-in-time grants, not standing role membership | Whole design |
| **AC-3** Access Enforcement | Enforce approved authorizations | The Cedar policy engine decides every request; the API enforces authorization per endpoint | `policies/aegis.cedar`, `tests/test_auth.py` |
| **AC-3(7)** Role-Based Access Control | | Role attributes (clearance, privileged, cross-department) | `policies/attributes.json` |
| **AC-3(13)** Attribute-Based Access Control | | Decisions use user, resource and context attributes | `evaluator.py` |
| **AC-5** Separation of Duties | Separate duties to reduce misuse | No self-approval; admins can't approve or edit themselves; auditors can't approve; alert subjects can't close their own alerts | `test_approver_eligibility`, `test_cannot_resolve_alert_about_yourself` |
| **AC-6** Least Privilege | Allow only necessary access | Scoped, time-bound grants; STS session policies for one action on one ARN; admins have no resource access | `credentials.py`, `test_iam_actions_follow_least_privilege` |
| **AC-6(1)** Authorize Access to Security Functions | | Restricted resources and privileged actions need a second person | `approval-required` policy |
| **AC-6(9)** Log Use of Privileged Functions | | Privileged grants, break-glass and credential issuance are all audited | `CREDENTIALS_ISSUED`, `BREAK_GLASS_USED` |
| **AC-6(10)** Prohibit Non-privileged Users from Executing Privileged Functions | | The `privileged-actions` guardrail | `test_deny_privileged_action_for_non_privileged_role` |
| **AU-2 / AU-3** Event Logging, Content | Log the relevant events with enough detail | Who (actor), whom (subject), what, which resource, when and why for every lifecycle event | `models.AuditLog` |
| **AU-6** Audit Review, Analysis, Reporting | | Detection rules, alert triage, access review | `detection.py`, `routers/governance.py` |
| **AU-9** Protection of Audit Information | Protect audit data from unauthorized modification | HMAC hash chain; Ed25519-signed checkpoints outside the database catch truncation; read access limited to oversight roles | `audit.py`, `checkpoints.py`, `test_audit_chain.py`, `test_hardening.py` |
| **AU-9(3)** Cryptographic Protection | | HMAC-SHA256 chain plus Ed25519 checkpoint signatures with a published public key | `checkpoints.py` |
| **AU-9(2)** Store on Separate Physical Systems | | SIEM push stream and pull export | `siem.py` |
| **AU-10** Non-repudiation | | Actor recorded on every event; STS `SourceIdentity` lands in CloudTrail | `credentials.py` |
| **AU-12** Audit Record Generation | | Written atomically with the change it describes (same transaction) | `audit.commit` |
| **CA-7** Continuous Monitoring | | Control checks in the access review (self-approvals, grants held by leavers, chain integrity) | `ControlChecks` |
| **CM-3** Configuration Change Control | | Policy changes are pinned by declarative test cases run in CI against both Cedar builds | `policies/tests.json`, `python -m app.policy_tests` |
| **CM-4** Impact Analyses | | What-if simulation shows how a role, department or classification change would alter a decision before it's made | `POST /policy/simulate`, `test_what_if_a_mover` |
| **SC-5** Denial-of-service Protection | | Per-caller rate limits on sign-in, MFA, access requests and simulation | `ratelimit.py` |
| **IA-2** Identification and Authentication | | OIDC tokens verified against the IdP's JWKS | `auth.py` |
| **IA-2(1)** Multi-factor Authentication to Privileged Accounts | | Restricted access, break-glass and approvals need a recent second factor (step-up) | `mfa-required` policy, `test_mfa.py` |
| **IA-2(8)** Replay-resistant Authentication | | TOTP time steps are single use | `test_codes_cannot_be_replayed` |
| **AC-7** Unsuccessful Logon Attempts | | Five wrong MFA codes lock the authenticator and raise an alert; an admin resets it | `test_brute_force_locks_and_alerts_then_admin_resets` |
| **IA-5** Authenticator Management | | No passwords stored; short-lived tokens; STS credentials never stored | `auth.py`, `credentials.py` |
| **SI-4** System Monitoring | | Six detection rules, including prompt injection and privilege escalation | `detection.py` |
| **SI-10** Information Input Validation | | Pydantic schemas; LLM input sanitized and output constrained | `schemas.py`, `llm_parser.py` |
| **SA-11** Developer Testing and Evaluation | | 100+ tests, SAST (Bandit, CodeQL), dependency scanning (pip-audit, Dependabot), coverage gate | `.github/workflows/` |

## SOC 2 (Trust Services Criteria)

| Criterion | Coverage |
|---|---|
| **CC6.1** Logical access security | Cedar ABAC, token authentication, least-privilege STS sessions |
| **CC6.2** Provisioning and deprovisioning | SCIM provisioning from the IdP and admin provisioning, both audited; the leaver process revokes all access |
| **CC6.3** Role changes and least privilege | Mover handling revokes access when attributes change; time-bound grants |
| **CC7.2** Monitoring for anomalies | Detection rules and alerts |
| **CC7.3** Evaluating security events | Alert triage (resolved or false positive, with notes) |
| **CC4.1** Monitoring of controls | Access review control checks; recertification campaigns with tracked outcomes |

## ISO/IEC 27001:2022 Annex A

| Control | Coverage |
|---|---|
| **5.15** Access control | Cedar policies |
| **5.16** Identity management | User lifecycle driven by the IdP over SCIM, with audit |
| **5.18** Access rights | JIT grants, approval, recertification campaigns that revoke unreviewed access, removal on change |
| **8.2** Privileged access rights | Approval required, break-glass with review, time limits |
| **8.3** Information access restriction | Department boundaries, clearance levels |
| **8.5** Secure authentication | OIDC/JWKS verification; MFA step-up for high-risk actions |
| **8.15** Logging | Hash-chained audit, SIEM export |
| **8.16** Monitoring activities | Detection rules |
