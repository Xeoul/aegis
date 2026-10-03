// Aegis-JIT dashboard. Plain DOM APIs only: every value from the API is rendered with
// textContent (never innerHTML), and the page runs under a strict CSP with no inline script.
"use strict";

const PERSONAS = [
  ["alice.chen@aegis.example", "Alice Chen", "engineer · eng"],
  ["bob.martinez@aegis.example", "Bob Martinez", "sre · eng"],
  ["maya.torres@aegis.example", "Maya Torres", "manager · eng"],
  ["eve.johansson@aegis.example", "Eve Johansson", "security"],
  ["grace.kim@aegis.example", "Grace Kim", "auditor"],
  ["frank.lee@aegis.example", "Frank Lee", "intern · mktg"],
  ["iris.novak@aegis.example", "Iris Novak", "identity admin"],
];
const OVERSIGHT = new Set(["auditor", "security engineer"]);
const state = { token: null, me: null, users: new Map(), tab: "request" };

// --- DOM helpers ---------------------------------------------------------------

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
// API timestamps are UTC; most are naive ("...T12:00:00"), a few carry an offset.
const parseTs = (ts) => new Date(/(Z|[+-]\d\d:\d\d)$/i.test(ts) ? ts : ts + "Z");
const fmt = (ts) => (ts ? parseTs(ts).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "—");
const who = (id) => (id == null ? "system" : state.users.get(id)?.name ?? `user ${id}`);

const TONE = {
  ACTIVE: "ok", ALLOW: "ok", RESOLVED: "ok", PENDING_APPROVAL: "warn", OPEN: "warn",
  DENIED: "bad", DENY: "bad", REJECTED: "bad", high: "bad", medium: "warn", low: "",
};
const st = (text, extra = "") => h("span", { class: `st ${TONE[text] ?? ""} ${extra}` }, text.replace(/_/g, " "));
const empty = (title, body) => h("div", { class: "empty" }, h("strong", {}, title), body);

function toast(msg) {
  const t = $("#toast");
  t.textContent = msg;
  t.classList.add("show");
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => t.classList.remove("show"), 3200);
}

// An inline prompt that replaces window.prompt: renders an input under `anchor`.
function ask(anchor, { placeholder, submit, tone = "primary" }, onSubmit) {
  anchor.parentElement.querySelector(".ask")?.remove();
  const input = h("input", { placeholder, required: true, minlength: "3", "aria-label": placeholder });
  const form = h("form", { class: "ask" }, input,
    h("button", { class: tone, type: "submit" }, submit),
    h("button", { class: "link", type: "button", onclick: () => form.remove() }, "cancel"));
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    form.querySelectorAll("button").forEach((b) => { b.disabled = true; });
    try { await onSubmit(input.value.trim()); } catch (e) { toast(e.message); form.querySelectorAll("button").forEach((b) => { b.disabled = false; }); }
  });
  anchor.after(form);
  input.focus();
}

// --- API -----------------------------------------------------------------------

async function api(path, opts = {}, retried = false) {
  const headers = { "content-type": "application/json" };
  if (state.token) headers.authorization = `Bearer ${state.token}`;
  const resp = await fetch(path, { ...opts, headers: { ...headers, ...(opts.headers || {}) } });
  const isJson = (resp.headers.get("content-type") || "").includes("json");
  const body = isJson ? await resp.json() : await resp.text();
  // RFC 9470 step-up: the action needs a recent second factor. Verify one, then retry once.
  if (resp.status === 401 && body?.detail?.error === "insufficient_user_authentication" && !retried) {
    if (await stepUp(body.detail.message)) return api(path, opts, true);
    throw new Error("Step-up cancelled: " + body.detail.message);
  }
  if (resp.status === 401 && state.token && !path.startsWith("/auth/")) { logout(); throw new Error("Session expired"); }
  if (!resp.ok) {
    const detail = isJson ? (typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)) : body;
    throw new Error(detail || resp.statusText);
  }
  return body;
}
const post = (path, data) => api(path, { method: "POST", body: JSON.stringify(data || {}) });

// --- MFA step-up -------------------------------------------------------------------

// Asks for a TOTP code in a dialog (enrolling an authenticator first if needed) and swaps the
// session token for one that records the second factor. Resolves false if cancelled.
async function stepUp(message) {
  let enrollment = null;
  if (!state.me?.mfa_enrolled) enrollment = await post("/auth/mfa/enroll");
  return new Promise((resolve) => {
    const code = h("input", { inputmode: "numeric", autocomplete: "one-time-code", pattern: "[0-9 ]{6,7}", maxlength: "7", required: true, placeholder: "123 456", "aria-label": "6-digit code" });
    const error = h("p", { class: "error", role: "alert" });
    const dialog = h("dialog", { class: "stepup" },
      h("form", { method: "dialog" },
        h("h2", {}, "Confirm it's you"),
        h("p", {}, message),
        enrollment && h("div", { class: "enroll" },
          h("p", {}, "First, add Aegis to your authenticator app with this key:"),
          h("code", {}, enrollment.secret.replace(/(.{4})/g, "$1 ").trim()),
          h("p", { class: "muted" }, enrollment.otpauth_uri)),
        h("label", {}, "Code from your authenticator app", code),
        error,
        h("div", { class: "row" },
          h("button", { class: "primary", value: "verify" }, "Verify"),
          h("button", { class: "ghost", value: "cancel", formnovalidate: true }, "Cancel"))));
    dialog.addEventListener("close", () => { dialog.remove(); resolve(dialog.returnValue === "ok"); });
    dialog.querySelector("form").addEventListener("submit", async (ev) => {
      if (ev.submitter?.value === "cancel") return;
      ev.preventDefault();
      try {
        const { access_token } = await post("/auth/step-up", { code: code.value.replace(/\s/g, "") });
        state.token = access_token;
        state.me = { ...state.me, mfa_enrolled: true };
        try { sessionStorage.setItem("aegis-token", access_token); } catch (_) { /* storage unavailable */ }
        dialog.close("ok");
      } catch (e) {
        error.textContent = e.message;
        code.select();
      }
    });
    document.body.append(dialog);
    dialog.showModal();
  });
}

// --- Theme ---------------------------------------------------------------------

function applyTheme(theme) {
  if (theme) document.documentElement.dataset.theme = theme;
  else delete document.documentElement.dataset.theme;
}
function toggleTheme() {
  const current = document.documentElement.dataset.theme
    || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
  const next = current === "dark" ? "light" : "dark";
  applyTheme(next);
  try { localStorage.setItem("aegis-theme", next); } catch (_) { /* storage unavailable */ }
}

// --- Auth ----------------------------------------------------------------------

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
  $("#app").hidden = true; $("#login").hidden = false;
}

const isOversight = (me) => me.is_admin || OVERSIGHT.has(me.role.toLowerCase());

async function start() {
  const [me, users] = await Promise.all([api("/me"), api("/users")]);
  state.me = me;
  state.users = new Map(users.map((u) => [u.id, u]));
  $("#whoami").replaceChildren(h("strong", {}, me.name), h("span", {}, `${me.role} · ${me.department}`.toLowerCase()));
  const tabs = [["request", "Request"], ["mine", "My access"], ["approvals", "Approvals"]];
  if (isOversight(me)) tabs.push(["alerts", "Alerts"], ["audit", "Audit log"], ["review", "Review"]);
  $("#tabs").replaceChildren(...tabs.map(([id, label]) =>
    h("button", { role: "tab", "data-tab": id, onclick: () => show(id) }, h("span", {}, label), h("span", { class: "count", hidden: true }))));
  $("#login").hidden = true; $("#app").hidden = false;
  show("request");
  refreshCounts();
}

async function refreshCounts() {
  const setCount = (tab, n) => {
    const el = document.querySelector(`#tabs [data-tab="${tab}"] .count`);
    if (el) { el.textContent = String(n); el.hidden = !n; }
  };
  try {
    setCount("approvals", (await api("/approvals")).length);
    if (isOversight(state.me)) setCount("alerts", (await api("/alerts")).length);
  } catch (_) { /* counts are cosmetic */ }
}

const LOADERS = { mine: loadMine, approvals: loadApprovals, alerts: loadAlerts, audit: loadAudit, review: loadReview };
function show(tab) {
  state.tab = tab;
  document.querySelectorAll("#tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === tab)));
  document.querySelectorAll(".panel").forEach((p) => { p.hidden = p.dataset.tab !== tab; });
  if (LOADERS[tab]) LOADERS[tab]().catch((e) => toast(e.message));
}

// --- Request -------------------------------------------------------------------

function reasonRow(text) {
  const m = /^\[([\w-]+)\]\s*(.*)$/.exec(text);
  return h("li", {}, h("span", { class: "pid" }, m ? m[1] : "note"), h("span", {}, m ? m[2] : text));
}

async function submitRequest(ev) {
  ev.preventDefault();
  const btn = ev.submitter; btn.disabled = true;
  try {
    const d = await post("/request-access", { request_text: $("#request-text").value, break_glass: $("#break-glass").checked });
    const tone = d.decision === "DENY" ? "bad" : d.status === "PENDING_APPROVAL" ? "warn" : "ok";
    const word = d.decision === "DENY" ? "denied" : d.status === "PENDING_APPROVAL" ? "pending" : "granted";
    const fact = (k, v) => h("div", { class: "fact" }, h("dt", {}, k), h("dd", {}, v));
    $("#decision").replaceChildren(h("div", { class: "verdict" },
      h("div", { class: "verdict-line" },
        h("span", { class: `verdict-word ${tone}` }, word),
        h("span", { class: "muted" }, {
          PENDING_APPROVAL: "awaiting a second approver",
          ACTIVE: "access is live",
          DENIED: `${d.reasons.length} guardrail${d.reasons.length === 1 ? "" : "s"} blocked this`,
        }[d.status] ?? d.status.toLowerCase()),
        d.break_glass ? h("span", { class: "tag bad" }, "break-glass") : null,
        ...d.risk_flags.map((f) => h("span", { class: "tag bad" }, `flag:${f}`))),
      h("dl", { class: "facts" },
        fact("resource", d.parsed.resource),
        fact("action", d.parsed.action),
        fact("sensitivity", d.policy.resource.sensitivity_level ?? "—"),
        fact("duration", d.decision === "DENY" ? "—" : `${d.policy.conditions.duration_hours}h`),
        fact("request", `#${d.request_id}`)),
      h("ul", { class: "reasons" }, d.reasons.map(reasonRow)),
      h("details", {}, h("summary", {}, `policy object · parsed by ${d.parser}`),
        h("pre", {}, JSON.stringify(d.policy, null, 2)))));
    $("#request-text").value = ""; $("#break-glass").checked = false;
    refreshCounts();
  } catch (e) { toast(e.message); } finally { btn.disabled = false; }
}

// --- My access -----------------------------------------------------------------

function clock(grant) {
  const total = Math.max(1, grant.duration_hours) * 3600e3;
  const fill = h("i");
  const bar = h("div", { class: "bar" }, fill);
  const left = h("b");
  const el = h("div", { class: "clock" }, bar, h("div", { class: "clock-text" }, h("span", {}, left, " remaining"), h("span", {}, `until ${fmt(grant.expires_at)}`)));
  const tick = () => {
    const ms = Math.max(0, parseTs(grant.expires_at) - Date.now());
    const m = Math.round(ms / 60e3);
    left.textContent = m >= 60 ? `${Math.floor(m / 60)}h ${String(m % 60).padStart(2, "0")}m` : `${m}m`;
    fill.style.width = `${Math.min(100, (ms / total) * 100)}%`;
    bar.classList.toggle("low", ms / total < 0.2);
  };
  tick();
  el.dataset.clock = "1";
  el.tick = tick;
  return el;
}
setInterval(() => document.querySelectorAll("[data-clock]").forEach((c) => c.tick?.()), 30e3);

async function loadMine() {
  const [grants, requests, resources] = await Promise.all([api("/active-grants"), api("/requests"), api("/resources")]);
  const aws = new Set(resources.filter((r) => r.aws_role_arn).map((r) => r.name));
  $("#grants").replaceChildren(h("div", { class: "rows" }, ...(grants.length ? grants.map((g) => {
    const actions = h("div", { class: "actions" },
      aws.has(g.resource) && g.user_id === state.me.id
        ? h("button", { class: "ghost", onclick: () => getCreds(g.id) }, "AWS credentials") : null,
      h("button", { class: "danger", onclick: (ev) => ask(ev.currentTarget.parentElement, { placeholder: "Why end this early?", submit: "Revoke", tone: "danger" },
        async (reason) => { await post(`/grants/${g.id}/revoke`, { reason }); toast("Revoked"); loadMine(); }) }, "Revoke"));
    return h("div", { class: "item" },
      h("div", { class: "item-top" },
        h("div", { class: "item-title" }, g.action, " ", h("span", { class: "muted" }, "on"), " ", h("span", { class: "mono" }, g.resource)),
        g.break_glass ? h("span", { class: "tag bad" }, "break-glass") : st("ACTIVE")),
      h("div", { class: "meta" }, `#${g.id} · ${g.allow_reason}`),
      clock(g), actions);
  }) : [empty("Nothing active.", "Zero standing privilege: access exists only while you need it.")])));
  $("#requests").replaceChildren(requests.length ? h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["#", "Resource", "Action", "Status", "Submitted"].map((c) => h("th", {}, c)))),
    h("tbody", {}, requests.map((r) => h("tr", {}, h("td", { class: "mono" }, r.id), h("td", { class: "mono" }, r.resource),
      h("td", {}, r.action), h("td", {}, st(r.status)), h("td", { class: "mono" }, fmt(r.created_at)))))))
    : empty("No history yet.", ""));
}

async function getCreds(id) {
  try {
    const c = await post(`/grants/${id}/credentials`);
    $("#creds").replaceChildren(h("div", { class: "verdict" },
      h("p", { class: "label" }, "Temporary AWS credentials · shown once"),
      h("div", { class: "meta" }, `${c.session_name} · ${c.role_arn} · expires ${fmt(c.expiration)}`),
      h("pre", {}, `export AWS_ACCESS_KEY_ID=${c.access_key_id}\nexport AWS_SECRET_ACCESS_KEY=${c.secret_access_key}\nexport AWS_SESSION_TOKEN=${c.session_token}`),
      h("details", {}, h("summary", {}, "session policy"), h("pre", {}, JSON.stringify(c.session_policy, null, 2)))));
  } catch (e) { toast(e.message); }
}

// --- Approvals -----------------------------------------------------------------

async function loadApprovals() {
  const tasks = await api("/approvals");
  $("#approvals").replaceChildren(h("div", { class: "rows" }, ...(tasks.length ? tasks.map(({ kind, eligibility, request: r }) => {
    const decide = (verb, tone, label) => (ev) => ask(ev.currentTarget.parentElement, { placeholder: "Comment for the audit trail", submit: label, tone },
      async (comment) => { const res = await post(`/requests/${r.id}/${verb}`, { comment }); toast(`#${r.id} → ${res.status.toLowerCase()}`); loadApprovals(); refreshCounts(); });
    return h("div", { class: "item" },
      h("div", { class: "item-top" },
        h("div", { class: "item-title" }, who(r.user_id), h("span", { class: "muted" }, " wants "), r.action, h("span", { class: "muted" }, " on "), h("span", { class: "mono" }, r.resource)),
        kind === "approval" ? st("PENDING_APPROVAL", "pulse") : h("span", { class: "tag bad" }, "break-glass review")),
      h("p", { class: "quote" }, `“${r.request_text}”`),
      h("div", { class: "meta" }, `${r.duration_hours}h · ${eligibility}`, r.risk_flags ? ` · flags: ${r.risk_flags}` : ""),
      h("div", { class: "actions" }, kind === "approval"
        ? [h("button", { class: "primary", onclick: decide("approve", "primary", "Approve") }, "Approve"),
          h("button", { class: "danger", onclick: decide("reject", "danger", "Reject") }, "Reject")]
        : [h("button", { class: "primary", onclick: decide("review", "primary", "Mark reviewed") }, "Review")]));
  }) : [empty("Inbox zero.", "Nothing needs your decision.")])));
}

// --- Oversight -----------------------------------------------------------------

async function loadAlerts() {
  const alerts = await api("/alerts");
  $("#alerts").replaceChildren(h("div", { class: "rows" }, ...(alerts.length ? alerts.map((a) => {
    const close = (fp) => (ev) => ask(ev.currentTarget.parentElement, { placeholder: "Resolution note", submit: fp ? "Mark false positive" : "Resolve" },
      async (note) => { await post(`/alerts/${a.id}/resolve`, { note, false_positive: fp }); toast("Alert closed"); loadAlerts(); refreshCounts(); });
    return h("div", { class: "item" },
      h("div", { class: "item-top" }, h("div", { class: "item-title mono" }, a.rule), st(a.severity)),
      h("p", { class: "quote" }, a.detail),
      h("div", { class: "meta" }, `${who(a.user_id)} · ${fmt(a.created_at)}`),
      h("div", { class: "actions" },
        h("button", { class: "ghost", onclick: close(false) }, "Resolve"),
        h("button", { class: "ghost", onclick: close(true) }, "False positive")));
  }) : [empty("All quiet.", "No open detections.")])));
}

async function loadAudit() {
  const logs = await api("/audit-logs?limit=50");
  $("#audit").replaceChildren(h("div", { class: "table-wrap" }, h("table", {},
    h("thead", {}, h("tr", {}, ["#", "Event", "Subject", "Actor", "Detail", "prev → hash"].map((c) => h("th", {}, c)))),
    h("tbody", {}, logs.map((e) => h("tr", {},
      h("td", { class: "mono" }, e.id),
      h("td", { class: "mono" }, e.event.toLowerCase().replace(/_/g, " ")),
      h("td", {}, e.user_id == null ? "—" : who(e.user_id)),
      h("td", {}, who(e.actor_id)),
      h("td", {}, e.detail),
      h("td", { class: "hash", title: e.hash }, e.prev_hash.slice(0, 6), " → ", h("b", {}, e.hash.slice(0, 6)))))))));
}

async function verifyChain() {
  try {
    const v = await api("/audit-logs/verify");
    const n = Math.min(v.entries_checked, 8);
    const links = h("div", { class: `links ${v.valid ? "" : "broken"}` }, ...Array.from({ length: n }, () => h("i")));
    $("#chain").replaceChildren(h("div", { class: "chain-status" }, links,
      h("span", { class: `st ${v.valid ? "ok" : "bad"}` }, v.valid ? "intact" : "tampered"),
      h("span", {}, v.valid
        ? `${v.entries_checked} entries verified · head `
        : `Tampering at entry #${v.first_invalid_id}: ${v.reason}`),
      v.valid ? h("span", { class: "hash" }, h("b", {}, v.head_hash.slice(0, 16))) : null));
  } catch (e) { toast(e.message); }
}

async function loadReview() {
  const r = await api("/reports/access-review?days=30");
  const c = r.control_checks;
  const kpi = (v, l, bad) => h("div", { class: "kpi" }, h("div", { class: `v ${bad ? "bad" : ""}` }, String(v)), h("div", { class: "l" }, l));
  $("#review").replaceChildren(
    h("div", { class: "kpis" },
      kpi(c.self_approvals, "self-approvals", c.self_approvals > 0),
      kpi(c.active_grants_for_inactive_users, "grants held by leavers", c.active_grants_for_inactive_users > 0),
      kpi(c.unreviewed_break_glass, "unreviewed break-glass", c.unreviewed_break_glass > 0),
      kpi(c.audit_chain_valid ? "ok" : "broken", "audit chain", !c.audit_chain_valid)),
    h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["User", "Active", "30d", "Denied", "Alerts", "Recommendation"].map((x) => h("th", {}, x)))),
      h("tbody", {}, r.users.map((u) => {
        const [verb, ...rest] = u.recommendation.split(":");
        const tone = { CERTIFY: "ok", INVESTIGATE: "warn", REVOKE: "bad" }[verb] ?? "";
        return h("tr", {},
          h("td", {}, h("div", {}, u.email.split("@")[0]), h("div", { class: "meta" }, u.role)),
          h("td", { class: "mono" }, u.active_grants.join(", ") || "—"),
          h("td", { class: "mono" }, u.grants_in_period), h("td", { class: "mono" }, u.denied_in_period),
          h("td", { class: "mono" }, u.open_alerts),
          h("td", {}, h("span", { class: `st ${tone}` }, verb.toLowerCase()), h("div", { class: "meta" }, rest.join(":").trim())));
      })))));
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

async function loadMeta() {
  try {
    const m = await api("/meta");
    if (!m.demo_mode) return;
    const parts = [h("b", {}, "Demo sandbox"), h("span", {}, "fictional company, people and data")];
    if (m.next_reset_at) {
      const mins = Math.max(0, Math.round((parseTs(m.next_reset_at) - Date.now()) / 60e3));
      parts.push(h("span", {}, `resets in ${mins >= 60 ? `${Math.floor(mins / 60)}h ${mins % 60}m` : `${mins}m`}`));
    }
    parts.push(h("span", {}, m.parser === "anthropic" ? "requests parsed by Claude" : "keyword parser (no LLM key)"));
    parts.push(h("span", {}, "production sign-in is your IdP via OIDC"));
    $("#banner").replaceChildren(...parts);
    $("#banner").hidden = false;
  } catch (_) { /* banner is informational */ }
}

try { applyTheme(localStorage.getItem("aegis-theme")); } catch (_) { /* storage unavailable */ }
loadMeta();
$("#personas").replaceChildren(...PERSONAS.map(([email, name, role]) =>
  h("button", { class: "persona", type: "button", onclick: () => login(email) },
    h("span", {}, name), h("span", { class: "role" }, role, " ", h("span", { class: "arrow" }, "→")))));
$("#login-form").addEventListener("submit", (ev) => { ev.preventDefault(); login($("#login-email").value); });
$("#request-form").addEventListener("submit", submitRequest);
$("#request-text").addEventListener("keydown", (ev) => {
  if (ev.key === "Enter" && (ev.metaKey || ev.ctrlKey)) $("#request-form").requestSubmit();
});
$("#verify").addEventListener("click", verifyChain);
$("#csv").addEventListener("click", downloadCsv);
$("#theme").addEventListener("click", toggleTheme);
$("#logout").addEventListener("click", logout);
try { state.token = sessionStorage.getItem("aegis-token"); } catch (_) { state.token = null; }
if (state.token) start().catch(logout);
