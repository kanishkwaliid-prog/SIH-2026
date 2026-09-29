// Shared across all 5 pages. Included as: <script src="../shared.js"></script>

const API_BASE = "http://localhost:8000";

// Folder that holds shared.js = the frontend root. Works whether pages are
// served by the backend (/app/...) or opened straight from disk.
const FRONTEND_ROOT = new URL(".", document.currentScript.src).href;

// Tailwind's `flex`/`grid` utilities out-rank the browser's default
// [hidden] rule, so an element like <form class="flex" hidden> would still
// show. This restores the attribute's meaning on every page.
(function () {
  const style = document.createElement("style");
  style.textContent = "[hidden]{display:none !important}";
  document.head.appendChild(style);
})();

// ---------- Escaping ----------
// Everything that came from the server or from an uploaded file (filenames,
// config lines, finding text, ...) must go through this before it is put
// into an innerHTML template -- in text position AND inside attribute
// values, hence both quote characters are escaped too.
function escapeHtml(value) {
  return String(value === null || value === undefined ? "" : value).replace(
    /[&<>"']/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c])
  );
}

// ---------- Vendors ----------
// One table for every page. `support: "full"` = parser verified against
// real exports (Cisco, Juniper, Palo Alto -- see README); everything else
// is parsed on a best-effort basis and marked experimental in the UI.
const VENDORS = [
  { id: "cisco_ios",         label: "Cisco IOS / NX-OS",  support: "full" },
  { id: "juniper_junos",     label: "Juniper Junos",      support: "full" },
  { id: "palo_alto",         label: "Palo Alto PAN-OS",   support: "full" },
  { id: "fortinet_fortios",  label: "Fortinet FortiOS",   support: "experimental" },
  { id: "arista_eos",        label: "Arista EOS",         support: "experimental" },
  { id: "huawei_vrp",        label: "Huawei VRP",         support: "experimental" },
  { id: "mikrotik_routeros", label: "MikroTik RouterOS",  support: "experimental" },
  { id: "checkpoint_gaia",   label: "Check Point Gaia",   support: "experimental" },
  { id: "netgate_pfsense",   label: "Netgate pfSense",    support: "experimental" },
  { id: "sonic",             label: "SONiC",              support: "experimental" },
];

function vendorInfo(id) {
  return VENDORS.find((v) => v.id === id) || null;
}

// Readable name for a backend vendor id; falls back to the raw id (or
// "Unknown") for a vendor this table doesn't know yet.
function vendorLabel(id) {
  const v = vendorInfo(id);
  return v ? v.label : id || "Unknown";
}

function isExperimentalVendor(id) {
  const v = vendorInfo(id);
  return !!v && v.support !== "full";
}

// ---------- Auth: token storage ----------
// Phase 0 decision 8: token in localStorage under "cg_token". The user
// object is cached next to it so the sidebar can render without waiting
// for the network; /auth/me refreshes it on every page load.

const TOKEN_KEY = "cg_token";
const USER_KEY = "cg_user";
const LOGIN_PAGE = FRONTEND_ROOT + "auth/login/index.html";
const HOME_PAGE = FRONTEND_ROOT + "upload_configuration/index.html";

function tokenPayload(token) {
  try {
    let part = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    while (part.length % 4) part += "=";
    return JSON.parse(atob(part));
  } catch (e) {
    return null;
  }
}

// Returns the token only if it exists and hasn't expired. The server is
// still the real judge -- this just avoids showing a page that will fail
// on its first API call.
function getToken() {
  const token = localStorage.getItem(TOKEN_KEY);
  if (!token) return null;
  const payload = tokenPayload(token);
  if (!payload || !payload.exp || payload.exp * 1000 <= Date.now()) {
    clearAuth();
    return null;
  }
  return token;
}

function getCurrentUser() {
  try {
    return JSON.parse(localStorage.getItem(USER_KEY));
  } catch (e) {
    return null;
  }
}

function saveAuth(token, user) {
  localStorage.setItem(TOKEN_KEY, token);
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  // Scans in this tab belong to whoever uploaded them. If a different
  // person signs in here, drop them -- the server would 404 them anyway
  // (Phase 2), and they shouldn't show up in the new user's screens.
  if (sessionStorage.getItem("sessions_owner") !== user.user_id) {
    sessionStorage.removeItem("sessions");
    sessionStorage.removeItem("uploadErrors");
    sessionStorage.removeItem(READ_KEY);
    sessionStorage.setItem("sessions_owner", user.user_id);
  }
}

function clearAuth() {
  localStorage.removeItem(TOKEN_KEY);
  localStorage.removeItem(USER_KEY);
}

function isPublicPage() {
  const here = window.location.href;
  return here.startsWith(FRONTEND_ROOT + "auth/") || here.startsWith(FRONTEND_ROOT + "legal/");
}

function isLegalPage() {
  return window.location.href.startsWith(FRONTEND_ROOT + "legal/");
}

// Sends the user to the login page, remembering where they were so they
// land back there afterwards. reason: "expired" shows a notice.
function redirectToLogin(reason) {
  const url = new URL(LOGIN_PAGE);
  if (!isPublicPage()) url.searchParams.set("next", window.location.href);
  if (reason) url.searchParams.set("reason", reason);
  window.location.replace(url.href);
}

function logout() {
  clearAuth();
  sessionStorage.removeItem("sessions");
  sessionStorage.removeItem("uploadErrors");
  sessionStorage.removeItem(READ_KEY);
  window.location.replace(LOGIN_PAGE);
}

// Only follow ?next= back into this app, never to another site.
function safeNextUrl() {
  const next = getUrlParam("next");
  if (next && next.startsWith(FRONTEND_ROOT) && !next.startsWith(FRONTEND_ROOT + "auth/")) {
    return next;
  }
  return HOME_PAGE;
}

// A promise that never settles. Returned after starting a redirect so the
// calling page's catch block (alerts, error text) never runs while the
// browser is navigating away.
function pendingForever() {
  return new Promise(() => {});
}

// ---------- Auth: API calls ----------

async function readError(response, fallback) {
  try {
    const body = await response.json();
    if (typeof body.detail === "string") return body.detail;
    if (Array.isArray(body.detail) && body.detail.length) {
      // FastAPI validation errors: "Value error, Password must be..."
      return body.detail.map((d) => String(d.msg).replace(/^Value error, /, "")).join(" ");
    }
  } catch (e) {
    /* not JSON */
  }
  return fallback;
}

// Fallback text for a failed response whose body had no usable `detail`
// (proxies and crashed servers often answer with plain text or HTML).
function statusFallback(what, status) {
  if (status === 413) return "That upload is too large for the server to accept.";
  if (status === 403) return "You don't have permission to do that.";
  if (status >= 500) return `${what}: the server hit an internal error (HTTP ${status}). Try again, and check the backend logs if it keeps happening.`;
  return `${what} (HTTP ${status}).`;
}

// Turns anything a page's catch block receives into a sentence for the
// user. fetch() rejects with a TypeError only when the server can't be
// reached at all; every other error already carries the server's message.
function describeError(err, fallback) {
  if (err instanceof TypeError) {
    return "Couldn't reach the analysis server. Make sure the backend is running (uvicorn api:app --port 8000) and try again.";
  }
  return (err && err.message) || fallback || "Something went wrong.";
}

// Every call to a protected endpoint goes through here.
//   401 -> token rejected: clear it and go to login (page code never sees it)
//   403 -> signed in but not allowed: thrown as an Error with the reason
async function authFetch(url, options = {}) {
  const token = getToken();
  if (!token) {
    redirectToLogin("expired");
    return pendingForever();
  }
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${token}`);
  const response = await fetch(url, Object.assign({}, options, { headers }));

  if (response.status === 401) {
    clearAuth();
    redirectToLogin("expired");
    return pendingForever();
  }
  if (response.status === 403) {
    throw new Error(await readError(response, "You don't have permission to do that."));
  }
  return response;
}

async function loginRequest(email, password) {
  const response = await fetch(`${API_BASE}/auth/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password }),
  });
  if (!response.ok) {
    throw new Error(await readError(response, "Couldn't sign in. Is the backend running?"));
  }
  const data = await response.json();
  if (data.status === "ok") saveAuth(data.access_token, data.user);
  return data; // Phase 3: data.status may be "mfa_required"
}

async function signupRequest({ email, password, name, orgName }) {
  const response = await fetch(`${API_BASE}/auth/signup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, password, name, org_name: orgName }),
  });
  if (!response.ok) {
    throw new Error(await readError(response, "Couldn't create the account. Is the backend running?"));
  }
  return response.json();
}

// ---------- Auth: 2FA (Phase 3) ----------
// mfaLoginRequest is the second sign-in step and, like loginRequest, is
// called before there's an access token -- it hits the API directly
// rather than through authFetch. Everything else here is an authFetch
// call made from an already-signed-in page (Security settings).

async function mfaLoginRequest(mfaToken, code) {
  const response = await fetch(`${API_BASE}/auth/2fa/login`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ mfa_token: mfaToken, code }),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data.detail || "Couldn't verify that code. Is the backend running?");
  }
  saveAuth(data.access_token, data.user);
  return data; // may include backup_codes_remaining
}

async function twoFactorSetup(password) {
  const response = await authFetch(`${API_BASE}/auth/2fa/setup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password }),
  });
  if (!response.ok) {
    throw new Error(await readError(response, "Couldn't start setup."));
  }
  return response.json(); // { secret, otpauth_uri, qr_code }
}

async function twoFactorVerify(code) {
  const response = await authFetch(`${API_BASE}/auth/2fa/verify`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
  if (!response.ok) {
    throw new Error(await readError(response, "Couldn't verify that code."));
  }
  return response.json(); // { enabled, backup_codes }
}

async function twoFactorStatus() {
  const response = await authFetch(`${API_BASE}/auth/2fa/status`);
  if (!response.ok) {
    throw new Error(await readError(response, "Couldn't load two-factor status."));
  }
  return response.json(); // { enabled, backup_codes_remaining }
}

async function regenerateBackupCodes(code) {
  const response = await authFetch(`${API_BASE}/auth/2fa/backup-codes`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ code }),
  });
  if (!response.ok) {
    throw new Error(await readError(response, "Couldn't generate new backup codes."));
  }
  return response.json(); // { backup_codes }
}

async function twoFactorDisable(password, code) {
  const response = await authFetch(`${API_BASE}/auth/2fa/disable`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ password, code }),
  });
  if (!response.ok) {
    throw new Error(await readError(response, "Couldn't turn off two-factor authentication."));
  }
  return response.json(); // { enabled: false }
}

// ---------- Roles ----------
// Mirrors ROLE_PERMISSIONS in backend auth/config.py. This is ONLY used to
// hide or disable controls the server would refuse anyway (it re-checks
// every request and answers 403) -- never treat it as security.

const ROLE_PERMISSIONS = {
  admin: ["upload", "confirm", "evaluate", "view_reports", "view_audit_log", "manage_users"],
  senior_engineer: ["upload", "confirm", "evaluate", "view_reports", "view_audit_log"],
  engineer: ["upload", "confirm", "evaluate", "view_reports"],
  viewer: ["view_reports"],
};

function userCan(user, permission) {
  return !!(user && (ROLE_PERMISSIONS[user.role] || []).includes(permission));
}

// ---------- Admin: team management (Phase 4) ----------

async function adminRequest(path, options, fallback) {
  const response = await authFetch(`${API_BASE}${path}`, options);
  if (!response.ok) throw new Error(await readError(response, fallback));
  return response.json();
}

function adminListUsers() {
  return adminRequest("/admin/users", {}, "Couldn't load team members.");
}

function adminAddUser({ email, name, password, role }) {
  return adminRequest("/admin/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ email, name, password, role }),
  }, "Couldn't add that member.");
}

function adminChangeRole(userId, role) {
  return adminRequest(`/admin/users/${encodeURIComponent(userId)}/role`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ role }),
  }, "Couldn't change that role.");
}

function adminResetTwoFactor(userId) {
  return adminRequest(`/admin/users/${encodeURIComponent(userId)}/reset-2fa`, { method: "POST" },
    "Couldn't reset two-factor authentication.");
}

// ---------- Activity log (Phase 5) ----------

function activityLog({ limit, beforeId } = {}) {
  const params = new URLSearchParams();
  if (limit) params.set("limit", limit);
  if (beforeId) params.set("before_id", beforeId);
  const qs = params.toString();
  return adminRequest(`/audit${qs ? `?${qs}` : ""}`, {}, "Couldn't load the activity log.");
}

async function refreshCurrentUser() {
  const response = await authFetch(`${API_BASE}/auth/me`);
  if (!response.ok) return getCurrentUser();
  const user = await response.json();
  localStorage.setItem(USER_KEY, JSON.stringify(user));
  return user;
}

// ---------- sessionStorage helpers ----------
// "sessions" = array of results from POST /upload, one per uploaded file.
// Each session object grows extra fields as it moves through the flow:
//   .session_id, .filename, .device, .config, .pending_confirmations (from /upload)
//   .findings, .warning (added after /evaluate)

function getSessions() {
  try {
    const parsed = JSON.parse(sessionStorage.getItem("sessions"));
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

function setSessions(sessions) {
  sessionStorage.setItem("sessions", JSON.stringify(sessions));
  refreshNotifications();
}

// /upload answers with one entry per file. A file the server refused
// (too large, not UTF-8) comes back as { filename, error } with no
// session_id/device, so it must never be stored as a session -- every page
// after the upload assumes sessions have a device.
function splitUploadResults(results) {
  const ok = [];
  const failed = [];
  (results || []).forEach((r) => {
    if (r && r.session_id && r.device && !r.error) ok.push(r);
    else failed.push({
      filename: (r && r.filename) || "Unnamed file",
      error: (r && r.error) || "The server couldn't process this file.",
    });
  });
  return { ok, failed };
}

function getUploadErrors() {
  try {
    const parsed = JSON.parse(sessionStorage.getItem("uploadErrors"));
    return Array.isArray(parsed) ? parsed : [];
  } catch (e) {
    return [];
  }
}

function setUploadErrors(list) {
  sessionStorage.setItem("uploadErrors", JSON.stringify(list || []));
  refreshNotifications();
}

function getSessionById(sessionId) {
  return getSessions().find((s) => s.session_id === sessionId) || null;
}

function updateSession(sessionId, patch) {
  const sessions = getSessions();
  const idx = sessions.findIndex((s) => s.session_id === sessionId);
  if (idx !== -1) {
    sessions[idx] = Object.assign({}, sessions[idx], patch);
    setSessions(sessions);
  }
}

function getUrlParam(name) {
  return new URLSearchParams(window.location.search).get(name);
}

// ---------- API calls ----------

async function uploadConfigs(fileTextEntries, vendorHint) {
  // fileTextEntries: [{ filename, text }, ...]
  const formData = new FormData();
  fileTextEntries.forEach((entry) => {
    const blob = new Blob([entry.text], { type: "text/plain" });
    formData.append("files", blob, entry.filename);
  });
  if (vendorHint) {
    formData.append("vendor_hint", vendorHint);
  }

  const response = await authFetch(`${API_BASE}/upload`, {
    method: "POST",
    body: formData,
  });
  if (!response.ok) {
    throw new Error(await readError(response, statusFallback("Upload failed", response.status)));
  }
  const data = await response.json();
  return data.results;
}

// The reviewer is whoever is signed in -- the server reads it from the
// token, so there is no confirmedBy argument any more.
async function confirmLines(sessionId, confirmations) {
  const response = await authFetch(`${API_BASE}/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: sessionId,
      confirmations: confirmations,
    }),
  });
  if (!response.ok) {
    throw new Error(await readError(response, statusFallback("Couldn't save the confirmations", response.status)));
  }
  return response.json();
}

async function evaluateSession(sessionId, frameworks) {
  const url = new URL(`${API_BASE}/evaluate/${sessionId}`);
  const list = Array.isArray(frameworks) ? frameworks.join(",") : frameworks;
  if (list) url.searchParams.set("frameworks", list);
  const response = await authFetch(url, { method: "POST" });
  if (!response.ok) {
    throw new Error(await readError(response, statusFallback("Evaluation failed", response.status)));
  }
  return response.json();
}

// A new tab can't send the Authorization header, so the PDF is fetched
// here and handed to the browser as a download.
async function downloadReportPdf(sessionId) {
  const response = await authFetch(`${API_BASE}/report/${sessionId}/pdf`);
  if (!response.ok) {
    throw new Error(await readError(response, `PDF download failed: ${response.status}`));
  }
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename = match ? match[1] : `compliance_report_${sessionId.slice(0, 8)}.pdf`;

  const blobUrl = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = blobUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 10000);
}

async function downloadReportFormat(sessionId, format) {
  const response = await authFetch(`${API_BASE}/report/${sessionId}/${format}`);
  if (!response.ok) {
    throw new Error(await readError(response, `${format.toUpperCase()} download failed: ${response.status}`));
  }
  const disposition = response.headers.get("Content-Disposition") || "";
  const match = disposition.match(/filename="?([^";]+)"?/);
  const filename = match ? match[1] : `compliance_report_${sessionId.slice(0, 8)}.${format}`;

  const blobUrl = URL.createObjectURL(await response.blob());
  const link = document.createElement("a");
  link.href = blobUrl;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(blobUrl), 10000);
}

// ---------- Central routing: decides which screen comes next ----------
// Called after upload, after a vendor confirmation, and after a batch of
// line confirmations -- always figures out the next unresolved step
// across ALL uploaded sessions (supports bulk upload).

function routeToNextStep() {
  const sessions = getSessions();

  const needsVendorConfirm = sessions.find((s) => s.device && s.device.needs_confirmation);
  if (needsVendorConfirm) {
    goTo(`../vendor_detection_result/index.html?session=${needsVendorConfirm.session_id}`);
    return;
  }

  const needsLineReview = sessions.find(
    (s) => s.pending_confirmations && s.pending_confirmations.length > 0
  );
  if (needsLineReview) {
    goTo(`../review_unknown_lines/index.html?session=${needsLineReview.session_id}`);
    return;
  }

  // Everything resolved -- go generate reports.
  goTo(`../compliance_report_dashboard/index.html`);
}

// ---------- Page transitions ----------
// The app is a set of static, separately-loaded HTML pages (no SPA
// router), so a true in-place transition isn't possible -- a real
// navigation always happens between them. This simulates one: the outer
// #app-shell fades/slides out before the browser navigates away, and
// fades/slides in on the next page's load, so it reads as a soft
// transition instead of a hard cut. Respects prefers-reduced-motion.

const PAGE_TRANSITION_MS = 220;

function prefersReducedMotion() {
  return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

// Use this instead of a raw `window.location.href = url` assignment for
// any same-app navigation (sidebar links, redirects after an action,
// etc.) so the exit transition plays consistently everywhere.
function goTo(url) {
  const shell = document.getElementById("app-shell");
  if (!shell || prefersReducedMotion()) {
    window.location.href = url;
    return;
  }
  shell.style.transition = `opacity ${PAGE_TRANSITION_MS}ms ease-in, transform ${PAGE_TRANSITION_MS}ms ease-in`;
  shell.style.opacity = "0";
  shell.style.transform = "translateY(-8px)";
  window.setTimeout(() => {
    window.location.href = url;
  }, PAGE_TRANSITION_MS);
}

function initPageTransitions() {
  const shell = document.getElementById("app-shell");
  if (!shell) return;

  if (prefersReducedMotion()) {
    shell.style.opacity = "1";
  } else {
    // Starts hidden via inline style="opacity:0" in the HTML (so there's
    // no flash before this runs), then eases in on the next frame.
    shell.style.transform = "translateY(8px)";
    requestAnimationFrame(() => {
      shell.style.transition = `opacity ${PAGE_TRANSITION_MS}ms ease-out, transform ${PAGE_TRANSITION_MS}ms ease-out`;
      requestAnimationFrame(() => {
        shell.style.opacity = "1";
        shell.style.transform = "translateY(0)";
      });
    });
  }

  // Any same-app link (relative .html href, no modifier keys, not
  // opening in a new tab) gets the fade-out treatment before navigating.
  document.addEventListener("click", (e) => {
    if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;

    const link = e.target.closest("a[href]");
    if (!link) return;
    if (link.target === "_blank" || link.hasAttribute("download")) return;

    const href = link.getAttribute("href");
    if (!href || href.startsWith("#") || href.startsWith("mailto:") || /^https?:\/\//.test(href)) return;

    e.preventDefault();
    goTo(link.href);
  });
}

// ---------- Signed-in user chip (sidebar) ----------
// Replaces the placeholder avatar with the user's initials; clicking it
// shows who is signed in and a sign-out button. Pages without the
// placeholder get the chip appended to the sidebar footer instead.

function initials(name) {
  return (name || "?")
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0].toUpperCase())
    .join("");
}

const ROLE_LABELS = {
  admin: "Admin",
  senior_engineer: "Senior engineer",
  engineer: "Engineer",
  viewer: "Viewer",
};

function renderUserChip(user) {
  if (!user) return;
  let slot = document.getElementById("cg-user-chip");
  if (!slot) {
    const placeholder = document.querySelector('img[alt="User profile"]');
    const footerRow = document.querySelector("aside .mt-auto > div:last-child");
    if (placeholder) {
      slot = placeholder.parentElement;
      slot.className = "relative ml-auto";
    } else if (footerRow) {
      slot = document.createElement("div");
      slot.className = "relative ml-auto";
      footerRow.appendChild(slot);
    } else {
      return;
    }
    slot.id = "cg-user-chip";
  }

  const esc = escapeHtml;
  slot.innerHTML = `
    <button type="button" id="cg-user-btn" aria-haspopup="true" aria-expanded="false"
      aria-label="Account: ${esc(user.name)}"
      class="w-8 h-8 rounded-full bg-secondary-container text-secondary border border-outline-variant flex items-center justify-center text-[12px] font-semibold hover:border-secondary focus:outline-none focus-visible:ring-2 focus-visible:ring-secondary transition-colors">
      ${esc(initials(user.name))}
    </button>
    <div id="cg-user-menu" role="menu" hidden
      class="absolute bottom-full right-0 mb-2 w-52 bg-surface-container-high border border-outline-variant rounded-xl p-md shadow-lg z-50">
      <p class="font-body-sm text-body-sm text-on-surface font-medium truncate">${esc(user.name)}</p>
      <p class="font-body-sm text-body-sm text-on-surface-variant truncate">${esc(user.email)}</p>
      <p class="mt-sm inline-flex px-2 py-0.5 rounded-full bg-surface-variant text-on-surface-variant text-[12px]">${esc(ROLE_LABELS[user.role] || user.role)}</p>
      <a href="${FRONTEND_ROOT}account/security/index.html" role="menuitem"
        class="mt-md w-full flex items-center justify-center gap-2 rounded-full border border-outline-variant py-2 font-body-sm text-body-sm text-on-surface hover:bg-surface-variant focus:outline-none focus-visible:ring-2 focus-visible:ring-secondary transition-colors">
        <span class="material-symbols-outlined text-[18px]">shield_lock</span>Security settings
      </a>
      <button type="button" id="cg-logout" role="menuitem"
        class="mt-sm w-full flex items-center justify-center gap-2 rounded-full border border-outline-variant py-2 font-body-sm text-body-sm text-on-surface hover:bg-surface-variant focus:outline-none focus-visible:ring-2 focus-visible:ring-secondary transition-colors">
        <span class="material-symbols-outlined text-[18px]">logout</span>Sign out
      </button>
    </div>`;

  const btn = document.getElementById("cg-user-btn");
  const menu = document.getElementById("cg-user-menu");
  const setOpen = (open) => {
    menu.hidden = !open;
    btn.setAttribute("aria-expanded", String(open));
  };
  btn.addEventListener("click", (e) => {
    e.stopPropagation();
    setOpen(menu.hidden);
  });
  document.addEventListener("click", (e) => {
    if (!slot.contains(e.target)) setOpen(false);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") setOpen(false);
  });
  document.getElementById("cg-logout").addEventListener("click", logout);
}

// Adds a "Team" link to the sidebar for users allowed to manage members.
function renderAdminNav(user) {
  if (!userCan(user, "manage_users")) return;
  const nav = document.querySelector("aside nav");
  if (!nav || nav.querySelector("[data-cg-admin-link]")) return;
  // Only the Team page itself: /admin/activity/ is also under /admin/ and
  // used to light up both entries.
  const active = window.location.href.startsWith(FRONTEND_ROOT + "admin/users/");
  const link = document.createElement("a");
  link.setAttribute("data-cg-admin-link", "");
  link.href = FRONTEND_ROOT + "admin/users/index.html";
  link.className = "flex items-center gap-3 px-3 py-2.5 rounded-full font-body-sm text-body-sm font-medium transition-colors " +
    (active ? "bg-primary text-on-primary" : "text-on-surface-variant hover:bg-surface-variant hover:text-on-surface");
  link.innerHTML = '<span class="material-symbols-outlined text-[18px]">group</span><span class="hidden md:inline">Team</span>';
  nav.appendChild(link);
}

// Adds an "Activity log" link to the sidebar for users allowed to view it.
// A sibling to renderAdminNav rather than an extension of it: the two
// permissions (manage_users, view_audit_log) are granted to different,
// only partly-overlapping sets of roles (senior_engineer gets the log but
// not Team; admin gets both).
function renderAuditNav(user) {
  if (!userCan(user, "view_audit_log")) return;
  const nav = document.querySelector("aside nav");
  if (!nav || nav.querySelector("[data-cg-audit-link]")) return;
  const active = window.location.href.startsWith(FRONTEND_ROOT + "admin/activity/");
  const link = document.createElement("a");
  link.setAttribute("data-cg-audit-link", "");
  link.href = FRONTEND_ROOT + "admin/activity/index.html";
  link.className = "flex items-center gap-3 px-3 py-2.5 rounded-full font-body-sm text-body-sm font-medium transition-colors " +
    (active ? "bg-primary text-on-primary" : "text-on-surface-variant hover:bg-surface-variant hover:text-on-surface");
  link.innerHTML = '<span class="material-symbols-outlined text-[18px]">history</span><span class="hidden md:inline">Activity log</span>';
  nav.appendChild(link);
}

// ---------- Engine status ----------
// The sidebar badge used to say "online" unconditionally. It now reflects
// GET /health: checked on load, every 30 s, and when the tab regains focus.

let engineState = "checking"; // "checking" | "online" | "offline"

function setEngineState(state) {
  engineState = state;
  const color = state === "online" ? "bg-tertiary" : state === "offline" ? "bg-error" : "bg-on-surface-variant";
  document.querySelectorAll("[data-cg-engine-dot]").forEach((dot) => {
    const ping = dot.children[0];
    const core = dot.children[1];
    [ping, core].forEach((el) => {
      if (!el) return;
      el.classList.remove("bg-tertiary", "bg-error", "bg-on-surface-variant");
      el.classList.add(color);
    });
    if (ping) ping.hidden = state !== "online"; // pulse only while healthy
  });
  document.querySelectorAll("[data-cg-engine-label]").forEach((el) => {
    el.textContent = state === "online" ? "online" : state === "offline" ? "offline" : "checking…";
    el.classList.toggle("text-error", state === "offline");
    el.classList.toggle("text-on-surface", state !== "offline");
  });
  refreshNotifications();
}

async function checkEngine() {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 4000);
  try {
    const response = await fetch(`${API_BASE}/health`, { signal: controller.signal, cache: "no-store" });
    const data = response.ok ? await response.json().catch(() => null) : null;
    setEngineState(data && data.status === "ok" ? "online" : "offline");
  } catch (e) {
    setEngineState("offline");
  } finally {
    clearTimeout(timer);
  }
}

function initEngineStatus() {
  setEngineState("checking");
  checkEngine();
  setInterval(checkEngine, 30000);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) checkEngine();
  });
}

// ---------- Notifications bell ----------
// Collects what the app already knows and used to drop on the floor:
// engine offline, files the server rejected at upload, and the warnings the
// evaluator attached to a scan.

const READ_KEY = "cg_notifications_read";

function readNotificationIds() {
  try {
    return new Set(JSON.parse(sessionStorage.getItem(READ_KEY)) || []);
  } catch (e) {
    return new Set();
  }
}

function collectNotifications() {
  const items = [];
  if (engineState === "offline") {
    items.push({
      id: "engine-offline", kind: "error", persistent: true,
      title: "Analysis engine unreachable",
      body: `Couldn't reach ${API_BASE}. Start the backend (uvicorn api:app --port 8000).`,
    });
  }
  getUploadErrors().forEach((e) => {
    items.push({
      id: `upload:${e.filename}:${e.error}`, kind: "error",
      title: `Not analysed: ${e.filename}`, body: e.error,
    });
  });
  getSessions().forEach((s) => {
    if (s && s.warning) {
      items.push({
        id: `warning:${s.session_id}:${s.warning}`, kind: "warning",
        title: `Warning for ${s.filename || "a scan"}`, body: String(s.warning),
      });
    }
  });
  return items;
}

function unreadNotifications() {
  const read = readNotificationIds();
  return collectNotifications().filter((n) => n.persistent || !read.has(n.id));
}

function refreshNotifications() {
  const bell = document.querySelector("[data-cg-bell]");
  if (!bell) return;
  const unread = unreadNotifications().length;
  let dot = bell.querySelector("[data-cg-bell-dot]");
  if (unread > 0 && !dot) {
    dot = document.createElement("span");
    dot.setAttribute("data-cg-bell-dot", "");
    dot.className = "absolute -top-0.5 -right-0.5 w-2 h-2 bg-error rounded-full border border-surface";
    bell.appendChild(dot);
  } else if (unread === 0 && dot) {
    dot.remove();
  }
  bell.title = unread ? `${unread} unread notification${unread > 1 ? "s" : ""}` : "Notifications";
  const panel = document.getElementById("cg-notif-panel");
  if (panel && !panel.hidden) renderNotificationPanel(panel);
}

function renderNotificationPanel(panel) {
  const items = collectNotifications();
  const read = readNotificationIds();
  const icons = { error: "error", warning: "warning" };
  const colors = { error: "text-error", warning: "text-medium" };
  const list = items.length
    ? items.map((n) => {
        const isRead = !n.persistent && read.has(n.id);
        return `<li class="flex gap-sm py-sm ${isRead ? "opacity-60" : ""}">
          <span class="material-symbols-outlined text-[18px] mt-0.5 ${colors[n.kind] || "text-on-surface-variant"}">${icons[n.kind] || "info"}</span>
          <div class="min-w-0">
            <p class="font-body-sm text-body-sm text-on-surface font-medium break-words">${escapeHtml(n.title)}</p>
            <p class="font-body-sm text-body-sm text-on-surface-variant break-words">${escapeHtml(n.body)}</p>
          </div>
        </li>`;
      }).join("")
    : `<li class="py-md font-body-sm text-body-sm text-on-surface-variant">You're all caught up. Warnings and upload problems will show up here.</li>`;
  const canMark = items.some((n) => !n.persistent && !read.has(n.id));
  panel.innerHTML = `
    <div class="flex items-center justify-between mb-xs">
      <h2 class="font-label-caps text-label-caps text-on-surface-variant">NOTIFICATIONS</h2>
      ${canMark ? '<button type="button" data-cg-mark-read class="font-body-sm text-body-sm text-primary hover:underline">Mark all as read</button>' : ""}
    </div>
    <ul class="divide-y divide-outline-variant">${list}</ul>`;
  const markBtn = panel.querySelector("[data-cg-mark-read]");
  if (markBtn) {
    markBtn.addEventListener("click", () => {
      const ids = new Set(readNotificationIds());
      collectNotifications().forEach((n) => { if (!n.persistent) ids.add(n.id); });
      sessionStorage.setItem(READ_KEY, JSON.stringify([...ids]));
      refreshNotifications();
    });
  }
}

function initNotifications() {
  const bell = document.querySelector('button[aria-label="Notifications"]');
  if (!bell || bell.hasAttribute("data-cg-bell")) return;
  bell.setAttribute("data-cg-bell", "");
  bell.classList.add("relative");
  bell.setAttribute("aria-haspopup", "dialog");
  bell.setAttribute("aria-expanded", "false");
  // Older markup had a permanent decorative red dot; the real one is
  // added by refreshNotifications() only when there is something unread.
  bell.querySelectorAll("span.bg-error").forEach((s) => s.remove());

  // Fixed-position and attached to <body>: the sidebar clips overflow.
  const panel = document.createElement("div");
  panel.id = "cg-notif-panel";
  panel.setAttribute("role", "dialog");
  panel.setAttribute("aria-label", "Notifications");
  panel.hidden = true;
  panel.className = "fixed z-50 max-h-96 overflow-y-auto bg-surface-container-high border border-outline-variant rounded-xl p-md shadow-lg";
  document.body.appendChild(panel);

  const setOpen = (open) => {
    if (open) {
      renderNotificationPanel(panel);
      const r = bell.getBoundingClientRect();
      const width = Math.min(320, window.innerWidth - 16);
      panel.style.width = width + "px";
      panel.style.left = Math.max(8, Math.min(r.left, window.innerWidth - width - 8)) + "px";
      panel.style.bottom = Math.max(8, window.innerHeight - r.top + 8) + "px";
    }
    panel.hidden = !open;
    bell.setAttribute("aria-expanded", String(open));
  };
  bell.addEventListener("click", (e) => {
    e.stopPropagation();
    setOpen(panel.hidden);
  });
  document.addEventListener("click", (e) => {
    if (!panel.hidden && !panel.contains(e.target) && !bell.contains(e.target)) setOpen(false);
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !panel.hidden) { setOpen(false); bell.focus(); }
  });
  window.addEventListener("resize", () => setOpen(false));
  refreshNotifications();
}

// ---------- Legal pages for signed-out visitors ----------
// Privacy / Terms / Help are public, but their markup carries the full app
// sidebar (Scans, Rulesets, ...), which is pointless -- and misleading --
// without a session. Swap it for a legal-only menu plus a Sign in link.

function applySignedOutLegalChrome() {
  const aside = document.querySelector("aside");
  if (!aside) return;
  const here = window.location.href;
  const item = (href, icon, label) => {
    const active = here.startsWith(href.replace(/index\.html$/, ""));
    return `<a href="${href}" class="flex items-center gap-3 px-3 py-2.5 rounded-full font-body-sm text-body-sm font-medium transition-colors ${
      active ? "bg-primary text-on-primary" : "text-on-surface-variant hover:bg-surface-variant hover:text-on-surface"
    }"><span class="material-symbols-outlined text-[18px]">${icon}</span><span class="hidden md:inline">${label}</span></a>`;
  };
  const nav = aside.querySelector("nav");
  if (nav) {
    nav.innerHTML =
      item(FRONTEND_ROOT + "legal/privacy/index.html", "policy", "Privacy Policy") +
      item(FRONTEND_ROOT + "legal/terms/index.html", "gavel", "Terms of Service") +
      item(FRONTEND_ROOT + "legal/help/index.html", "help", "Help Center") +
      item(LOGIN_PAGE, "login", "Sign in");
  }
  const label = aside.querySelector("span.font-label-caps");
  if (label) label.textContent = "LEGAL";
  const footerBlock = aside.querySelector(".mt-auto");
  if (footerBlock) footerBlock.remove();
  const brand = aside.querySelector("a[href]");
  if (brand) brand.setAttribute("href", LOGIN_PAGE);
}

function initChrome() {
  if (isPublicPage()) {
    if (isLegalPage() && !getToken()) applySignedOutLegalChrome();
    return;
  }
  initEngineStatus();
  initNotifications();
}

// ---------- Page guard ----------
// Runs as soon as shared.js loads (it is included before each page's own
// script). Protected pages without a valid token redirect immediately and
// never fade in.

function initAuth() {
  if (isPublicPage()) return true;
  const hadToken = !!localStorage.getItem(TOKEN_KEY);
  if (!getToken()) {
    redirectToLogin(hadToken ? "expired" : null);
    return false;
  }
  const render = (user) => {
    renderUserChip(user);
    renderAdminNav(user);
    renderAuditNav(user);
  };
  const renderCached = () => render(getCurrentUser());
  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", renderCached);
  else renderCached();
  refreshCurrentUser().then((user) => {
    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", () => render(user));
    else render(user);
  }).catch(() => {});
  return true;
}

if (initAuth()) {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initPageTransitions);
    document.addEventListener("DOMContentLoaded", initChrome);
  } else {
    initPageTransitions();
    initChrome();
  }
}
