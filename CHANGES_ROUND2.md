# Round 2 fixes (frontend only, on top of the Block 1 fixes)

Copy `src/frontend/` over your project's `src/frontend/` (same as last time).

1. Bug 19 - empty review page: a session with no pending lines now skips to the next step
   (next session with lines, or the dashboard). Back/Forward cache restores are re-checked.
   A "Nothing left to review" message + Continue button shows if the redirect is slow.
2. Rulesets: ISO/IEC 27001:2022 section added (7 rules, matches iso27001_rules.yaml);
   stats now 6 frameworks / 54 rules; interpretive-mapping note mentions ISO.
3. Mobile controls: the bell, engine status and account menu (the only Sign out) were
   `hidden md:flex`, so phones had none of them. shared.js now builds one footer block for every
   signed-in page: icon-only engine dot on phones (text in title/aria-label), 36px tap targets.
   Sidebar top bar wraps on narrow screens. Account menu and bell panel open downward on phones
   (upward on desktop) and are clamped on-screen. Only one of the two panels is open at a time.
4. Signed-in legal pages: Privacy/Terms/Help now show the account chip, bell, engine status and
   the Team / Activity log links (role-based). They never redirect to login.
5. Apply button / picker: larger button (min 88x36, text-sm), readable labels, wraps on small
   screens; the button no longer changes width between "Apply" and "Running...".
6. Leftover upload: pendingUpload is cleared as soon as the server answers (accepted, all
   rejected, or 4xx/5xx), so refresh can't re-submit. Kept only on a real network failure.
7. Unknown vendor label: null/"unknown" -> "Unrecognised vendor" (heading: "Vendor not
   recognised"); unmapped ids are prettified instead of shown raw.
