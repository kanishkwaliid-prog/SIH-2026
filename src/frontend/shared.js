// Shared across all 5 pages. Included as: <script src="../shared.js"></script>

const API_BASE = "http://localhost:8000";

// ---------- sessionStorage helpers ----------
// "sessions" = array of results from POST /upload, one per uploaded file.
// Each session object grows extra fields as it moves through the flow:
//   .session_id, .filename, .device, .config, .pending_confirmations (from /upload)
//   .findings, .warning (added after /evaluate)

function getSessions() {
  const raw = sessionStorage.getItem("sessions");
  return raw ? JSON.parse(raw) : [];
}

function setSessions(sessions) {
  sessionStorage.setItem("sessions", JSON.stringify(sessions));
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

  const response = await fetch(`${API_BASE}/upload`, {
    method: "POST",
    body: formData,
  });
  if (!response.ok) {
    throw new Error(`Upload failed: ${response.status}`);
  }
  const data = await response.json();
  return data.results;
}

async function confirmLines(sessionId, confirmations, confirmedBy) {
  const response = await fetch(`${API_BASE}/confirm`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      session_id: sessionId,
      confirmations: confirmations,
      confirmed_by: confirmedBy || "demo-user",
    }),
  });
  if (!response.ok) {
    throw new Error(`Confirm failed: ${response.status}`);
  }
  return response.json();
}

async function evaluateSession(sessionId, frameworks) {
  const url = new URL(`${API_BASE}/evaluate/${sessionId}`);
  const list = Array.isArray(frameworks) ? frameworks.join(",") : frameworks;
  if (list) url.searchParams.set("frameworks", list);
  const response = await fetch(url, { method: "POST" });
  if (!response.ok) {
    throw new Error(`Evaluate failed: ${response.status}`);
  }
  return response.json();
}

function reportPdfUrl(sessionId) {
  return `${API_BASE}/report/${sessionId}/pdf`;
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

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initPageTransitions);
} else {
  initPageTransitions();
}
