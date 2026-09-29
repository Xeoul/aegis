// Aegis-JIT access policy.
//
// Model: one baseline permit ("an active employee may request anything in the catalog")
// constrained by forbid guardrails. In Cedar a matching forbid always overrides a permit, so
// each guardrail is independent, and every guardrail that fires is reported as a reason.
// @reason annotations are the human-readable explanations returned by the API.

@id("baseline-active-employee")
@reason("Active employees may request catalog resources, subject to the guardrails below.")
permit (principal is User, action, resource is Resource)
when { principal.active };

@id("clearance")
@reason("The requester's role is not cleared for this resource's sensitivity level.")
forbid (principal is User, action, resource is Resource)
when { principal.role.clearance < resource.sensitivity };

@id("privileged-actions")
@reason("delete and admin are privileged actions and require a privileged role.")
forbid (principal is User, action in [Action::"delete", Action::"admin"], resource)
unless { principal.role.privileged };

@id("department-boundary")
@reason("Confidential and restricted resources are limited to their owning department.")
forbid (principal is User, action, resource is Resource)
when {
  resource.sensitivity >= 3 &&
  resource has owner_department &&
  resource.owner_department != principal.department
}
unless { principal.role.cross_department };

@id("justification-required")
@reason("Restricted resources require a business justification.")
forbid (principal, action, resource is Resource)
when { resource.sensitivity >= 4 && !context.has_justification };

@id("approval-required")
@reason("Restricted resources and privileged actions need a second person to approve.")
forbid (principal, action, resource is Resource)
when { resource.sensitivity >= 4 || action in [Action::"delete", Action::"admin"] }
unless { context.approved };
