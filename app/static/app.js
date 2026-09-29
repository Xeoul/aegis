// Aegis-JIT dashboard. Plain DOM APIs only: every value from the API is rendered with
// textContent (never innerHTML), and the page runs under a strict CSP with no inline script.
"use strict";

const PERSONAS = [
  ["alice.chen@aegis.example", "Alice Chen", "Engineer · Engineering"],
  ["bob.martinez@aegis.example", "Bob Martinez", "SRE · Engineering"],
  ["maya.torres@aegis.example", "Maya Torres", "Manager · Engineering (approver)"],
  ["eve.johansson@aegis.example", "Eve Johansson", "Security engineer (approver, triage)"],
  ["grace.kim@aegis.example", "Grace Kim", "Auditor · Compliance"],
  ["frank.lee@aegis.example", "Frank Lee", "Intern · Marketing"],
  ["iris.novak@aegis.example", "Iris Novak", "Identity admin · IT"],
];
const OVERSIGHT = new Set(["auditor", "security engineer"]);
const state = { token: null, me: null, users: new Map() };
const who = (id) => (id == null ? "system" : state.users.get(id)?.name ?? `user #${id}`);

function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") el.className = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else if (v !== false && v != null) el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of children.flat()) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}
const $ = (sel) => document.querySelector(sel);
const fmt = (ts) => (ts ? new Date(ts.endsWith("Z") ? ts : ts + "Z").toLocaleString() : "-");

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 3500);
}

async function api(path, opts = {}) {
  const headers = { "content-type": "application/json" };
  if (state.token) headers.authorization = `Bearer ${state.token}`;
  const resp = await fetch(path, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
  if (resp.status === 401 && state.token) { logout(); throw new Error("Session expired"); }
  const isJson = (resp.headers.get("content-type") || "").includes("json");
  const body = isJson ? await resp.json() : await resp.text();
  if (!resp.ok) {
    const detail = isJson ? (typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)) : body;
    throw new Error(detail || resp.statusText);
  }
  return body;
}
const post = (path, data) => api(path, { method: "POST", body: JSON.stringify(data || {}) });

const STATUS_CLASS = { ACTIVE: "ok", ALLOW: "ok", RESOLVED: "ok", PENDING_APPROVAL: "warn", OPEN: "warn",
  DENIED: "bad", DENY: "bad", REJECTED: "bad", REVOKED: "", EXPIRED: "", high: "bad", medium: "warn", low: "" };
const badge = (text) => h("span", { class: `badge ${STATUS_CLASS[text] ?? ""}` }, text);
const empty = (text) => h("div", { class: "empty" }, text);

// --- Auth -----------------------------------------------------------------------

async function login(email) {
  $("#login-error").textContent = "";
  try {
    const { access_token } = await post("/auth/dev-token", { email });
    state.token = access_token;
    try { sessionStorage.setItem("aegis-token", access_token); } catch (_) { /* storage unavailable */ }
    await start();
  } catch (e) {
    $("#login-error").textContent = e.message;
  }
}

function logout() {
  state.token = null; state.me = null;
  try { sessionStorage.removeItem("aegis-token"); } catch (_) { /* ignore */ }
  $("#app").hidden = true; $("#login").hidden = false; $("#whoami").replaceChildren();
}

function isOversight(me) { return me.is_admin || OVERSIGHT.has(me.role.toLowerCase()); }

async function start() {
  const [me, users] = await Promise.all([api("/me"), api("/users")]);
  state.me = me;
  state.users = new Map(users.map((u) => [u.id, u]));
  $("#whoami").replaceChildren(...[
    h("span", {}, h("strong", {}, me.name), " ", h("span", { class: "muted" }, `${me.role} · ${me.department}`)),
    me.is_admin ? badge("admin") : null,
    h("button", { class: "secondary", onclick: logout }, "Sign out"),
  ].filter(Boolean));
  const tabs = [["request", "Request access"], ["mine", "My access"], ["approvals", "Approvals"]];
  if (isOversight(me)) tabs.push(["alerts", "Alerts"], ["audit", "Audit"], ["review", "Access review"]);
  $("#tabs").replaceChildren(...tabs.map(([id, label]) =>
    h("button", { role: "tab", "data-tab": id, onclick: () => show(id) }, label)));
  $("#login").hidden = true; $("#app").hidden = false;
  show("request");
}

const LOADERS = { mine: loadMine, approvals: loadApprovals, alerts: loadAlerts, audit: loadAudit, review: loadReview };
function show(tab) {
  document.querySelectorAll("#tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
  document.querySelectorAll(".panel").forEach((p) => { p.hidden = p.dataset.tab !== tab; });
  if (LOADERS[tab]) LOADERS[tab]().catch((e) => toast(e.message));
}

// --- Request -------------------------------------------------------------------

async function submitRequest(ev) {
  ev.preventDefault();
  const btn = ev.submitter; btn.disabled = true;
  try {
    const d = await post("/request-access", { request_text: $("#request-text").value, break_glass: $("#break-glass").checked });
    $("#decision").replaceChildren(
      h("div", { class: "item" },
        h("div", { class: "row" }, badge(d.decision), badge(d.status), d.break_glass ? badge("break-glass") : null,
          ...d.risk_flags.map((f) => h("span", { class: "badge bad" }, `flag: ${f}`)),
          h("span", { class: "muted" }, `request #${d.request_id} · parser: ${d.parser}`)),
        h("ul", { class: "reasons" }, d.reasons.map((r) => h("li", {}, r))),
        h("details", {}, h("summary", { class: "muted" }, "Resolved ABAC policy"),
          h("pre", {}, JSON.stringify(d.policy, null, 2)))));
    $("#request-text").value = ""; $("#break-glass").checked = false;
  } catch (e) { toast(e.message); } finally { btn.disabled = false; }
}

// --- My access -----------------------------------------------------------------

async function loadMine() {
  const [grants, requests, resources] = await Promise.all([api("/active-grants"), api("/requests"), api("/resources")]);
  const aws = new Set(resources.filter((r) => r.aws_role_arn).map((r) => r.name));
  $("#grants").replaceChildren(...(grants.length ? grants.map((g) => h("div", { class: "item" },
    h("div", {}, h("strong", {}, `${g.action} on ${g.resource}`), " ", g.break_glass ? badge("break-glass") : null),
    h("div", { class: "meta" }, `#${g.id} · expires ${fmt(g.expires_at)} · ${g.allow_reason}`),
    h("div", { class: "actions" },
      aws.has(g.resource) && g.user_id === state.me.id
        ? h("button", { class: "secondary", onclick: () => getCreds(g.id) }, "Get AWS credentials") : null,
      h("button", { class: "danger", onclick: () => revoke(g.id) }, "Revoke")))) : [empty("No active grants. Zero standing privilege.")]));
  $("#requests").replaceChildren(...(requests.length ? [h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["#", "Resource", "Action", "Status", "Submitted", "Reason"].map((c) => h("th", {}, c)))),
    h("tbody", {}, requests.map((r) => h("tr", {}, h("td", {}, r.id), h("td", {}, r.resource), h("td", {}, r.action),
      h("td", {}, badge(r.status)), h("td", {}, fmt(r.created_at)), h("td", {}, r.decision_comment || r.revoke_reason || r.allow_reason))))))]
    : [empty("No requests yet.")]));
}

async function revoke(id) {
  const reason = prompt("Reason for revoking this grant early?");
  if (!reason) return;
  try { await post(`/grants/${id}/revoke`, { reason }); toast("Grant revoked"); loadMine(); } catch (e) { toast(e.message); }
}

async function getCreds(id) {
  try {
    const c = await post(`/grants/${id}/credentials`);
    $("#creds").replaceChildren(h("div", { class: "card" },
      h("h2", {}, "Temporary AWS credentials"),
      h("p", { class: "muted" }, `Session ${c.session_name} on ${c.role_arn}, valid until ${fmt(c.expiration)}. Shown once; Aegis does not store them.`),
      h("pre", {}, `export AWS_ACCESS_KEY_ID=${c.access_key_id}\nexport AWS_SECRET_ACCESS_KEY=${c.secret_access_key}\nexport AWS_SESSION_TOKEN=${c.session_token}`),
      h("details", {}, h("summary", { class: "muted" }, "Session policy"), h("pre", {}, JSON.stringify(c.session_policy, null, 2)))));
  } catch (e) { toast(e.message); }
}

// --- Approvals -----------------------------------------------------------------

async function loadApprovals() {
  const tasks = await api("/approvals");
  $("#approvals").replaceChildren(...(tasks.length ? tasks.map(({ kind, eligibility, request: r }) => h("div", { class: "item" },
    h("div", { class: "row" }, badge(kind === "approval" ? "PENDING_APPROVAL" : "break-glass review"),
      h("strong", {}, `${r.action} on ${r.resource}`), h("span", { class: "muted" }, `${who(r.user_id)} · request #${r.id}`)),
    h("div", {}, `“${r.request_text}”`),
    h("div", { class: "meta" }, `${eligibility} · ${r.duration_hours}h · submitted ${fmt(r.created_at)}`,
      r.risk_flags ? ` · flags: ${r.risk_flags}` : ""),
    h("div", { class: "actions" }, kind === "approval"
      ? [h("button", { onclick: () => decide(r.id, "approve") }, "Approve"), h("button", { class: "danger", onclick: () => decide(r.id, "reject") }, "Reject")]
      : [h("button", { onclick: () => decide(r.id, "review") }, "Mark reviewed")])))
    : [empty("Nothing waiting for you.")]));
}

async function decide(id, verb) {
  const comment = prompt(`Comment for ${verb} (min 3 characters)`);
  if (!comment) return;
  try { const r = await post(`/requests/${id}/${verb}`, { comment }); toast(`Request #${id}: ${r.status}`); loadApprovals(); } catch (e) { toast(e.message); }
}

// --- Oversight -----------------------------------------------------------------

async function loadAlerts() {
  const alerts = await api("/alerts");
  $("#alerts").replaceChildren(...(alerts.length ? alerts.map((a) => h("div", { class: "item" },
    h("div", { class: "row" }, badge(a.severity), h("strong", {}, a.rule), h("span", { class: "muted" }, `${who(a.user_id)} · ${fmt(a.created_at)}`)),
    h("div", {}, a.detail),
    h("div", { class: "actions" },
      h("button", { class: "secondary", onclick: () => resolveAlert(a.id, false) }, "Resolve"),
      h("button", { class: "secondary", onclick: () => resolveAlert(a.id, true) }, "False positive"))))
    : [empty("No open alerts.")]));
}

async function resolveAlert(id, falsePositive) {
  const note = prompt("Resolution note");
  if (!note) return;
  try { await post(`/alerts/${id}/resolve`, { note, false_positive: falsePositive }); toast("Alert closed"); loadAlerts(); } catch (e) { toast(e.message); }
}

async function loadAudit() {
  const logs = await api("/audit-logs?limit=50");
  $("#audit").replaceChildren(h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["#", "Time", "Event", "User", "Actor", "Resource", "Detail", "Hash"].map((c) => h("th", {}, c)))),
    h("tbody", {}, logs.map((e) => h("tr", {}, h("td", {}, e.id), h("td", {}, fmt(e.timestamp)), h("td", {}, e.event),
      h("td", {}, e.user_id == null ? "-" : who(e.user_id)), h("td", {}, who(e.actor_id)), h("td", {}, e.resource ?? "-"),
      h("td", {}, e.detail), h("td", {}, h("code", { title: e.hash }, e.hash.slice(0, 10) + "…"))))))));
}

async function verifyChain() {
  try {
    const v = await api("/audit-logs/verify");
    $("#chain").replaceChildren(h("p", {},
      h("span", { class: `badge ${v.valid ? "ok" : "bad"}` }, v.valid ? "VALID" : "TAMPERED"), " ",
      v.valid ? `Chain intact: ${v.entries_checked} entries, head ${v.head_hash.slice(0, 16)}…`
        : `Tampering detected at entry #${v.first_invalid_id}: ${v.reason}`));
  } catch (e) { toast(e.message); }
}

async function loadReview() {
  const r = await api("/reports/access-review?days=30");
  const c = r.control_checks;
  const kpi = (v, l, bad) => h("div", { class: "kpi" }, h("div", { class: `v ${bad ? "error" : ""}` }, String(v)), h("div", { class: "l" }, l));
  $("#review").replaceChildren(
    h("div", { class: "kpis" },
      kpi(c.self_approvals, "Self-approvals", c.self_approvals > 0),
      kpi(c.active_grants_for_inactive_users, "Grants held by leavers", c.active_grants_for_inactive_users > 0),
      kpi(c.unreviewed_break_glass, "Unreviewed break-glass", c.unreviewed_break_glass > 0),
      kpi(c.audit_chain_valid ? "Intact" : "Broken", "Audit chain", !c.audit_chain_valid)),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["User", "Role", "Active grants", "Grants (30d)", "Denied", "Open alerts", "Recommendation"].map((x) => h("th", {}, x)))),
      h("tbody", {}, r.users.map((u) => h("tr", {}, h("td", {}, u.email), h("td", {}, `${u.role} · ${u.department}`),
        h("td", {}, u.active_grants.join(", ") || "-"), h("td", {}, u.grants_in_period), h("td", {}, u.denied_in_period),
        h("td", {}, u.open_alerts), h("td", {}, u.recommendation)))))));
}

async function downloadCsv(ev) {
  ev.preventDefault();
  try {
    const csv = await api("/reports/access-review?format=csv");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv" }));
    h("a", { href: url, download: "access-review.csv" }).click();
    URL.revokeObjectURL(url);
  } catch (e) { toast(e.message); }
}

// --- Boot ----------------------------------------------------------------------

$("#personas").replaceChildren(...PERSONAS.map(([email, name, desc]) =>
  h("button", { class: "persona", type: "button", onclick: () => login(email) }, h("strong", {}, name), h("span", {}, desc))));
$("#login-form").addEventListener("submit", (ev) => { ev.preventDefault(); login($("#login-email").value); });
$("#request-form").addEventListener("submit", submitRequest);
$("#verify").addEventListener("click", verifyChain);
$("#csv").addEventListener("click", downloadCsv);
try { state.token = sessionStorage.getItem("aegis-token"); } catch (_) { state.token = null; }
if (state.token) start().catch(logout);
