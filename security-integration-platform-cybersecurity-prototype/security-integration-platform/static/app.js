"use strict";
// SECURITY: all API data is rendered with textContent (never innerHTML); the token lives in memory only.
let token = null, me = null, tab = "dashboard", dataTable = "users", editorText = "";
const RANK = { viewer: 1, analyst: 2, admin: 3 };
const $ = (id) => document.getElementById(id);
const rank = () => RANK[me?.role] || 0;

function el(tag, attrs, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v);
  }
  for (const k of kids.flat()) if (k != null && k !== false) n.append(k.nodeType ? k : document.createTextNode(String(k)));
  return n;
}
function toast(msg) { const t = $("toast"); t.textContent = msg; t.classList.add("show"); setTimeout(() => t.classList.remove("show"), 4500); }

async function api(path, opts = {}) {
  const headers = { Accept: "application/json" };
  if (token) headers.Authorization = "Bearer " + token;
  if (opts.body) headers["Content-Type"] = "application/json";
  const res = await fetch(path, { method: opts.method || "GET", headers, body: opts.body ? JSON.stringify(opts.body) : undefined, credentials: "omit" });
  let data = null; try { data = await res.json(); } catch { /* non-JSON */ }
  if (res.status === 401 && token) { signOut("Session expired - please sign in again."); throw new Error("Unauthenticated"); }
  if (!res.ok) throw new Error(typeof data?.detail === "string" ? data.detail : "Request failed (" + res.status + ")");
  return data;
}
const show = (id, on) => $(id).classList.toggle("hidden", !on);
function signOut(msg) { token = me = null; show("app", false); show("login", true); $("login-err").textContent = msg || ""; $("p").value = ""; }

$("login-form").addEventListener("submit", async (e) => {
  e.preventDefault(); $("login-err").textContent = "";
  try {
    const r = await api("/auth/login", { method: "POST", body: { username: $("u").value, password: $("p").value } });
    token = r.token; me = { username: r.username, role: r.role }; $("p").value = "";
    $("who").textContent = me.username + " (" + me.role + ")";
    show("login", false); show("app", true); buildTabs(); render();
  } catch (err) { $("login-err").textContent = err.message; }
});
$("logout").addEventListener("click", async () => { try { await api("/auth/logout", { method: "POST" }); } catch { /* ignore */ } signOut(""); });

const TABS = [["dashboard", "Dashboard", 1], ["data", "Data", 1], ["vulnlookup", "Package vulnerability lookup", 2], ["runs", "Runs", 1], ["quarantine", "Quarantine", 2], ["connectors", "Add / edit connector", 2], ["secrets", "Secrets", 3], ["actions", "Response actions", 1]];
function go(id) { tab = id; buildTabs(); render(); }
function buildTabs() {
  const nav = $("tabs"); nav.replaceChildren();
  for (const [id, label, min] of TABS) if (rank() >= min) nav.append(el("button", { class: id === tab ? "on" : "", onclick: () => go(id) }, label));
}
const pill = (s) => el("span", { class: "pill " + (s || "never") }, (s || "never").replaceAll("_", " "));
const fmt = (v) => v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v);
function table(cols, rows) {
  return el("div", { class: "scroll" }, el("table", {}, el("thead", {}, el("tr", {}, cols.map((c) => el("th", {}, c[0])))),
    el("tbody", {}, rows.length ? rows.map((r) => el("tr", {}, cols.map((c) => el("td", {}, c[1](r))))) : el("tr", {}, el("td", { colspan: cols.length, class: "muted" }, "Nothing here yet.")))));
}
async function render() {
  const v = $("view"); v.replaceChildren(el("p", { class: "muted" }, "Loading..."));
  try { v.replaceChildren(await views[tab]()); } catch (e) { v.replaceChildren(el("p", { class: "err" }, e.message)); }
}
const ago = (iso) => { if (!iso) return ""; const s = Math.round((Date.now() - Date.parse(iso)) / 1000); return s < 90 ? s + "s ago" : s < 5400 ? Math.round(s / 60) + " min ago" : Math.round(s / 3600) + " h ago"; };

const views = {
  async dashboard() {
    const [c, h] = await Promise.all([api("/connectors"), api("/health/connectors")]);
    const latest = Object.fromEntries(h.connectors.map((x) => [x.source, x]));
    const cards = c.connectors.map((k) => {
      const run = latest[k.name], out = el("pre", { class: "hidden mono" });
      const test = el("button", { class: "ghost", onclick: async (ev) => {
        ev.target.disabled = true; ev.target.textContent = "Testing...";
        try {
          const r = await api("/connectors/" + encodeURIComponent(k.id) + "/test", { method: "POST" });
          out.textContent = r.ok ? "OK: " + r.records_on_first_page + " records on page 1 in " + r.elapsed_ms + " ms; " + r.invalid_in_sample + " invalid in sample\n" + JSON.stringify(r.sample, null, 1) + (r.invalid_reasons.length ? "\nInvalid: " + r.invalid_reasons.join("; ") : "") : "FAILED: " + r.error;
          out.classList.remove("hidden");
        } catch (e) { toast(e.message); }
        ev.target.disabled = false; ev.target.textContent = "Test connection";
      } }, "Test connection");
      const sync = el("button", { onclick: async (ev) => {
        ev.target.disabled = true; ev.target.textContent = "Syncing...";
        try { const r = await api("/sync/" + encodeURIComponent(k.id), { method: "POST" }); toast(k.name + ": fetched " + r.records_fetched + ", saved " + r.records_saved + ", invalid " + r.invalid_records); }
        catch (e) { toast(k.name + ": " + e.message); }
        render();
      } }, "Sync now");
      if (rank() < 2 || !k.valid) { sync.disabled = true; test.disabled = true; }
      if (!k.enabled) sync.disabled = true;
      const edit = rank() >= 2 && k.valid ? el("button", { class: "ghost", onclick: async () => { try { editorText = (await api("/connectors/" + encodeURIComponent(k.id) + "/yaml")).yaml; go("connectors"); } catch (e) { toast(e.message); } } }, "Edit config") : null;
      const needs = (k.secrets || []).map((s) => el("span", { class: s.set ? "set" : "missing" }, s.name + (s.set ? " \u2713" : s.optional ? " (optional, not set)" : " (missing)") + " "));
      return el("div", { class: "card" },
        el("div", { class: "row" }, el("h2", {}, k.name), el("span", { class: "spacer" }), !k.valid ? pill("failed") : !k.enabled ? el("span", { class: "pill disabled-pill" }, "disabled") : pill(run?.status)),
        k.valid ? el("p", { class: "muted" }, "entity: " + k.entity + " \u00b7 auth: " + k.auth_type + " \u00b7 paging: " + k.pagination + " \u00b7 schedule: " + (k.schedule || "manual") + (k.next_run ? " (next " + new Date(k.next_run).toLocaleTimeString() + ")" : "")) : el("p", { class: "err" }, k.error),
        needs.length ? el("p", { class: "muted" }, "Secrets: ", needs) : null,
        run ? el("p", { class: "muted" }, "last run " + ago(run.finished_at || run.started_at) + " \u00b7 fetched " + run.records_fetched + " \u00b7 saved " + run.records_saved + " \u00b7 invalid " + run.invalid_records) : (k.valid ? el("p", { class: "muted" }, "Never run.") : null),
        run?.consecutive_failures >= 3 ? el("p", { class: "alert" }, "\u26a0 " + run.consecutive_failures + " failures in a row") : null,
        run?.error ? el("p", { class: "err" }, run.error) : null,
        el("div", { class: "row" }, test, sync, edit), out);
    });
    return el("div", {}, el("h2", {}, c.connectors.length + " connector(s)"), el("div", { class: "grid" }, cards));
  },
  async data() {
    const sel = el("select", { onchange: (e) => { dataTable = e.target.value; render(); } }, ["users", "devices", "events"].map((x) => { const o = el("option", { value: x }, x); o.selected = x === dataTable; return o; }));
    const r = await api("/tables/" + dataTable + "?limit=200");
    const cols = r.rows.length ? Object.keys(r.rows[0]) : [];
    return el("div", { class: "card" }, el("div", { class: "row" }, el("h2", {}, "Common-schema tables"), sel, el("span", { class: "muted" }, r.total + " rows total, newest 200 shown")),
      table(cols.map((k) => [k, (x) => fmt(x[k])]), r.rows));
  },
  async vulnlookup() {
    const name = el("input", { name: "package_name", placeholder: "Package name (e.g. fastapi)", required: "" });
    const ecosystem = el("select", { name: "ecosystem" }, ["PyPI", "npm", "Go", "Maven", "NuGet", "RubyGems", "crates.io", "Packagist", "Hex", "Pub"].map((x) => el("option", { value: x }, x)));
    const version = el("input", { name: "version", placeholder: "Version (e.g. 0.115.0)", required: "" });
    const out = el("pre", { class: "hidden mono" });
    const form = el("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault(); const button = e.submitter; button.disabled = true; button.textContent = "Checking...";
      try {
        const r = await api("/osv/query", { method: "POST", body: { package_name: name.value.trim(), ecosystem: ecosystem.value, version: version.value.trim() } });
        out.textContent = JSON.stringify(r, null, 2) + "\n\nAdvisories are saved under Data → events (vulnerability records).";
        out.classList.remove("hidden"); toast("OSV lookup complete: " + r.vulnerabilities_found + " advisories found.");
      } catch (err) { out.textContent = "Lookup failed: " + err.message; out.classList.remove("hidden"); }
      button.disabled = false; button.textContent = "Check package";
    } }, el("h2", {}, "Check an open-source package version"),
      el("p", { class: "muted" }, "Queries the public OSV.dev vulnerability database. No API key is required."),
      el("div", { class: "formgrid" }, el("label", {}, "Package name", name), el("label", {}, "Ecosystem", ecosystem), el("label", {}, "Version", version)),
      el("button", { type: "submit" }, "Check package"));
    return el("div", {}, form, el("div", { class: "card" }, el("h2", {}, "Lookup result"), out));
  },
  async runs() {
    const r = await api("/runs?limit=100");
    return el("div", { class: "card" }, el("h2", {}, "Sync history"), table([["#", (x) => x.id], ["Source", (x) => x.source], ["Status", (x) => pill(x.status)], ["Started", (x) => x.started_at], ["Fetched", (x) => x.records_fetched], ["Saved", (x) => x.records_saved], ["Invalid", (x) => x.invalid_records], ["Error", (x) => x.error || ""]], r.runs));
  },
  async quarantine() {
    const r = await api("/invalid-records?limit=100");
    return el("div", { class: "card" }, el("h2", {}, "Quarantined records (failed mapping)"), table([["Source", (x) => x.source], ["Reason", (x) => x.reason], ["Raw record", (x) => JSON.stringify(x.record)]], r.invalid_records));
  },
  async connectors() {
    const admin = rank() >= 3, out = el("pre", { class: "hidden mono" });
    const say = (t) => { out.textContent = t; out.classList.remove("hidden"); };
    const ta = el("textarea", { spellcheck: "false", placeholder: "Paste connector YAML, or upload a .yaml file..." }); ta.value = editorText;
    const file = el("input", { type: "file", accept: ".yaml,.yml,text/yaml" });
    file.addEventListener("change", () => { const f = file.files[0]; if (!f || f.size > 262144) return toast("Choose a .yaml file under 256 KB."); const rd = new FileReader(); rd.onload = () => { ta.value = String(rd.result); }; rd.readAsText(f); });
    const over = el("input", { type: "checkbox" });
    const post = (body) => api("/connectors", { method: "POST", body });
    const yamlCard = el("div", { class: "card" }, el("h2", {}, "Connector YAML"), ta,
      el("div", { class: "row" }, file,
        el("button", { class: "ghost", onclick: async () => { try { const r = await post({ config: ta.value, validate_only: true }); say("\u2714 valid: " + r.name); } catch (e) { say("\u2718 " + e.message); } } }, "Validate"),
        admin ? el("label", { class: "chk" }, over, "overwrite if exists") : null,
        admin ? el("button", { onclick: async () => { try { const r = await post({ config: ta.value, overwrite: over.checked }); toast("Saved connector " + r.id); editorText = ""; go("dashboard"); } catch (e) { say("\u2718 " + e.message); } } }, "Save connector") : el("span", { class: "muted" }, "Admins can save.")));
    if (!admin) return el("div", {}, yamlCard, out);
    const f = (label, name, ph = "", val = "") => el("label", {}, label, el("input", { name, placeholder: ph, value: val }));
    const sel = (label, name, opts) => el("label", {}, label, el("select", { name }, opts.map((o) => el("option", { value: o }, o))));
    const form = el("form", { class: "card", onsubmit: async (e) => {
      e.preventDefault(); const d = Object.fromEntries(new FormData(e.target).entries());
      try {
        const spec = { name: d.name, base_url: d.base_url, auth: { type: d.auth_type }, endpoint: { path: d.path, method: "GET" }, pagination: { type: d.pag_type }, mapping: { entity: d.entity, fields: {}, required: [] } };
        if (d.auth_type === "bearer" || d.auth_type === "api_key") { spec.auth.secret = d.secret; if (d.header) spec.auth.header = d.header; }
        if (d.auth_type === "basic") { spec.auth.username_env = d.username_env; spec.auth.password_env = d.password_env; }
        if (d.auth_type !== "none" && d.optional) spec.auth.optional = true;
        if (d.params.trim()) spec.endpoint.params = JSON.parse(d.params);
        for (const k of ["items_path", "next_path", "page_param", "start_param", "limit_param", "cursor_param"]) if (d[k]) spec.pagination[k] = d[k];
        for (const k of ["page_size", "max_pages"]) if (d[k]) spec.pagination[k] = Number(d[k]);
        if (d.schedule) spec.schedule = d.schedule;
        for (const line of d.mapping.split("\n").map((l) => l.trim()).filter(Boolean)) {
          const i = line.indexOf("="); if (i < 1) throw new Error("Mapping line needs 'target = source.path': " + line);
          const target = line.slice(0, i).trim(), rhs = line.slice(i + 1).trim();
          if (rhs.startsWith("const:")) spec.mapping.fields[target] = { value: rhs.slice(6).trim() };
          else if (rhs.includes("|")) { const [p, c] = rhs.split("|").map((x) => x.trim()); spec.mapping.fields[target] = { path: p, convert: c }; }
          else spec.mapping.fields[target] = rhs;
        }
        spec.mapping.required = d.required.split(",").map((x) => x.trim()).filter(Boolean);
        const r = await post({ spec, overwrite: false }); toast("Saved connector " + r.id); go("dashboard");
      } catch (er) { say("\u2718 " + er.message); }
    } },
      el("h2", {}, "Or build one with a form"),
      el("div", { class: "formgrid" }, f("Name", "name", "my_firewall"), f("Base URL (https)", "base_url", "https://api.vendor.com"), f("Endpoint path", "path", "/v1/users"),
        sel("Auth type", "auth_type", ["none", "bearer", "api_key", "basic"]), f("Secret name", "secret", "CONNECTOR_VENDOR_TOKEN"), f("API-key header", "header", "X-API-Key"),
        f("Basic: username secret", "username_env", "CONNECTOR_X_USER"), f("Basic: password secret", "password_env", "CONNECTOR_X_PASS"),
        el("label", { class: "chk" }, el("input", { type: "checkbox", name: "optional" }), "auth optional"),
        f("Query params (JSON)", "params", '{"limit":100}'),
        sel("Pagination", "pag_type", ["none", "page", "offset", "cursor", "link_header"]), f("Items path", "items_path", "results"), f("Next path (cursor)", "next_path", "meta.next"),
        f("page_param", "page_param", "page"), f("start_param (offset)", "start_param", "startAt"), f("limit_param", "limit_param", "limit"), f("cursor_param", "cursor_param", "cursor"),
        f("Page size", "page_size", "100"), f("Max pages", "max_pages", "10"), f("Schedule", "schedule", "15m"), sel("Entity", "entity", ["user", "device", "event", "alert", "vulnerability", "ticket"])),
      el("label", {}, "Mapping - one per line: target = source.path   |   target = path | date   |   target = const:text", el("textarea", { name: "mapping", placeholder: "id = id\nemail = profile.login\nlast_login = lastLogin | date" })),
      el("label", {}, "Required fields (comma separated)", el("input", { name: "required", placeholder: "id,email" })),
      el("div", { class: "row" }, el("button", { type: "submit" }, "Create connector")));
    return el("div", {}, yamlCard, form, out);
  },
  async secrets() {
    const r = await api("/secrets");
    const name = el("input", { placeholder: "CONNECTOR_NVD_API_KEY", maxlength: "70" }), val = el("input", { type: "password", placeholder: "secret value (write-only)", autocomplete: "off" });
    return el("div", {},
      el("div", { class: "card" }, el("h2", {}, "Add or replace a secret"),
        el("div", { class: "row" }, name, val, el("button", { onclick: async () => { try { await api("/secrets/" + encodeURIComponent(name.value.trim()), { method: "PUT", body: { value: val.value } }); val.value = ""; toast("Secret saved (encrypted)."); render(); } catch (e) { toast(e.message); } } }, "Save")),
        el("p", { class: "muted" }, "Stored encrypted on this machine; values are never shown again or written to logs. Names must start with CONNECTOR_.")),
      el("div", { class: "card" }, el("h2", {}, "Stored secrets"), table([["Name", (x) => x], ["", (x) => el("button", { class: "bad", onclick: async () => { try { await api("/secrets/" + encodeURIComponent(x), { method: "DELETE" }); render(); } catch (e) { toast(e.message); } } }, "Delete")]], r.secrets)));
  },
  async actions() {
    const approvals = await api("/approvals");
    const mk = (fields, label, handler) => el("form", { class: "row", onsubmit: async (e) => { e.preventDefault(); const f = new FormData(e.target); let params; try { params = JSON.parse(f.get("params") || "{}"); } catch { return toast("Parameters must be valid JSON."); } try { await handler(f, params); } catch (er) { toast(er.message); } } },
      fields.map(([n, p, req]) => el("input", req ? { name: n, placeholder: p, required: "" } : { name: n, placeholder: p })), el("button", { type: "submit" }, label));
    const out = el("pre", { class: "hidden mono" });
    const request = mk([["c", "connector (e.g. jsonplaceholder_test)", 1], ["a", "action (e.g. isolate_host)", 1], ["params", '{"host_id":"h1"}']], "Request approval", async (f, params) => { const r = await api("/approvals", { method: "POST", body: { connector_name: f.get("c"), action_name: f.get("a"), parameters: params } }); toast("Approval requested: " + r.approval_id); render(); });
    const prep = mk([["c", "connector", 1], ["a", "action", 1], ["params", '{"host_id":"h1"}'], ["id", "approval id"]], "Dry-run", async (f, params) => { const r = await api("/actions/prepare", { method: "POST", body: { connector_name: f.get("c"), action_name: f.get("a"), parameters: params, approval_id: f.get("id") || null } }); out.textContent = JSON.stringify(r, null, 2); out.classList.remove("hidden"); });
    if (rank() < 2) { request.classList.add("hidden"); prep.classList.add("hidden"); }
    const decide = (id, d) => async () => { try { await api("/approvals/" + encodeURIComponent(id) + "/decision", { method: "POST", body: { decision: d } }); render(); } catch (e) { toast(e.message); } };
    return el("div", {},
      el("div", { class: "card" }, el("h2", {}, "Request approval"), request, el("p", { class: "muted" }, "Actions are defined server-side. Only dry-run plans are produced; nothing is ever sent to a vendor.")),
      el("div", { class: "card" }, el("h2", {}, "Prepare (dry-run) an approved action"), prep, out),
      el("div", { class: "card" }, el("h2", {}, "Approvals"), table([["ID", (x) => x.approval_id], ["Connector", (x) => x.connector_name], ["Action", (x) => x.action_name], ["Requested by", (x) => x.requested_by], ["Status", (x) => pill(x.status)], ["Expires", (x) => x.expires_at],
        ["", (x) => x.status === "PENDING" && rank() >= 3 && x.requested_by !== me.username ? el("div", { class: "row" }, el("button", { onclick: decide(x.approval_id, "APPROVED") }, "Approve"), el("button", { class: "bad", onclick: decide(x.approval_id, "REJECTED") }, "Reject")) : ""]], approvals.approvals)));
  },
};
show("login", true);
