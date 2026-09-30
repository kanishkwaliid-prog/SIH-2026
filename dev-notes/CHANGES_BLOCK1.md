# Block 1 fixes (frontend only — no backend changes)

Drop the `src/frontend/` folder over the project's `src/frontend/`.
`src/frontend/legal/help/Untitled` was a stray file and is deleted (not in this zip; delete it in your copy too).

## Apply button / ruleset picker (compliance_report_dashboard)
- Technical View persists after Apply (view is tracked in a variable and re-applied after each render).
- No boxes ticked: Apply is disabled and a message explains why; it no longer silently runs CIS.
- Double-click: only one evaluation can run; Apply, checkboxes and the device picker lock while it runs.
- PDF/JSON/CSV/MD buttons are disabled for the whole re-evaluation, and on failure.
- ISO 27001 checkbox added (sends `ISO27001`, which the backend already supports).

## Nav
- Settings now goes to account/security on all 9 pages (was `href="#"`); account + admin pages show Settings too (replaces the "Security" entry, same target).
- Activity log page highlights only "Activity log".

## Vendors
- One VENDORS table in shared.js: Cisco / Juniper / Palo Alto = fully supported, other 7 = experimental.
- Upload + switch-vendor dropdowns are grouped Fully supported / Experimental; a note appears when an experimental vendor is picked.
- Rulesets: "10 Vendors Supported" with Full / Experimental lists. Help text updated to match.
- Dashboard + vendor page show proper labels for all 10 vendors, plus an EXPERIMENTAL badge.
- Backend `warning` from /evaluate is now shown on the dashboard and in the bell.

## Security (script injection)
- New `escapeHtml()` in shared.js (escapes & < > " '), applied to: review-page raw lines, value input, tooltip, options; dashboard device picker, rule id, field, explanation, observed value, remediation CLI.
- XML lines now display literally instead of only their inner text; quotes no longer break the value input / tooltip.

## Functional
- Per-file upload errors (too large / not UTF-8) are kept out of sessions, listed per file, and no longer hang the dashboard. If some files succeed, the dashboard loads them and lists the rejected ones.
- Upload / confirm / evaluate failures show the server's own message (413, 403, 500 ...). "Couldn't reach the analysis server" is now only for real network failures.
- Confirm failures show inline on the review page instead of a generic alert.
- Finding cards actually collapse (click or Enter/Space).
- Notifications bell works: engine offline, rejected uploads, evaluator warnings; unread badge; mark all read.
- "Engine online" is driven by GET /health (on load, every 30 s, on tab focus).

## Layout
- Legal pages show a legal-only sidebar (Privacy / Terms / Help / Sign in) to signed-out visitors; signed-in users still get the app sidebar.

## Files changed
shared.js and every page under src/frontend except auth/login and auth/signup.
