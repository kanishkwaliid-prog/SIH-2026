# ConfigGuard -- progress notes

Phases 0, 1, 2 done (see docs/auth_decisions.md). This file tracks Phase 3
onward.

## Phase 3: TOTP 2FA -- built; fixes applied, test run still pending

Backend and frontend are built (details in `docs/auth_decisions.md` section 6).
The Phase 3 test suite had 6 failures when it was first run; the cause is fixed:

- **Root cause of the 6 failing tests:** `POST /auth/2fa/verify` called
  `store.record_totp_step()`, so confirming enrollment used up the current
  30-second step. Any sign-in / backup-code regeneration / disable with the
  same or the previous code was then rejected as a "replay". Enrollment no
  longer records a step.
- `record_totp_step` now returns whether it advanced, and `_check_totp_code`
  rejects when it didn't (the "two concurrent requests" guarantee in the docs
  was not actually enforced before -- the return value was ignored).
- The `mfa_pending` token is now spent only on a *correct* code. Before, a
  single typo burned it and forced a full re-login, contradicting the login
  page's retry behaviour. Spent ids are pruned after expiry.
- `enable_totp` is idempotent under concurrent `/verify` calls.

### Still to do for Phase 3

1. Run `cd src/backend && pytest auth/ -q` locally. The fixes below were made
   in an environment with no network (no fastapi/pytest), so they were only
   syntax-checked (`py_compile`, `node --check`) and reviewed by hand.
2. Click through the browser flow once (enroll, sign out, sign in with a code
   and with a backup code, wrong code then right code, Back link, regenerate,
   disable, admin reset). Also confirm the login page shows only one form at a
   time -- `shared.js` now forces `[hidden]{display:none}` because Tailwind's
   `flex` class otherwise overrides the attribute.
3. Add the 2FA flow to `submission/DEMO.md`.
4. Leave the `# Phase 5: log_event(...)` comments in `routes.py` and
   `admin_routes.py`.

## Phase 4: RBAC -- implemented, awaiting test run

- `auth/deps.py`: `require_permission(Permission.X)`. Applied to every
  endpoint in `api.py` (see docs section 10). A viewer can no longer upload,
  confirm or evaluate.
- `auth/admin_routes.py` (+ `store.py` helpers): list / add members, change
  role (last-admin guard, org-scoped), admin reset of a member's 2FA.
- `src/frontend/admin/users/index.html`: minimal Team page; a "Team" sidebar
  link appears for admins (`shared.js`). The upload page disables itself for
  viewers.
- `auth/test_rbac.py`: permission matrix, role change applies to an old
  token, forged role claim ignored, admin endpoints and org scoping, and a
  test that fails if any new route has no permission.
- Two existing tests were edited because they relied on the old open
  behaviour: `test_tenant_isolation.py` uploaded as a viewer, and
  `test_auth_flow.py` voted with a non-schema field (`ssh_version`).

## Other bugs fixed along the way (`auth/test_hardening.py`)

- Review consensus grouped votes by line only, so votes for *different*
  answers added up and promoted an arbitrary one. Votes now combine only when
  field and value match.
- `/confirm`: a bad item midway through a batch discarded earlier promoted
  results from the session; unknown fields could be promoted into org memory.
  The batch is validated first and the session is updated per item.
- `/evaluate`: unknown framework names were silently dropped, giving an empty
  "clean" report; now `400`.
- `/upload`: no limits (now 20 files x 10 MB); a UTF-8 BOM broke matching of
  the first config line (now decoded with `utf-8-sig`).

## Phase 5: activity log -- built (backend + tests + docs + frontend); test suite not run in this environment; Phase 6 not started

**Phase 5 is fully written.** Same limitation as every prior pass: no
network in this build environment, so `pytest auth/ -q` has not actually
been executed -- only `py_compile` (all backend `.py` files) and
`node --check` (`shared.js` and the new page's inline script), both clean,
plus manual review.

- New `src/backend/activity_log.py`: `activity_log` table (org_id,
  actor_user_id, actor_role, event_type, target, detail, timestamp,
  prev_hash, entry_hash), indexed on `(org_id, id)`. `log_event()`,
  `list_activity_log()` (paginated, newest first, `before_id` cursor),
  `verify_activity_chain()`. The hash chain literally imports and reuses
  `block2b.review_system._compute_hash` (not a reimplementation) so both
  chains are guaranteed to hash identically.
- `api.py`: calls `activity_log.init_activity_log_table()` at startup;
  `log_event()` wired into upload (per-file success + both rejection
  paths), confirm (per item), evaluate, PDF download; new `GET /audit`
  endpoint (`require_permission(Permission.VIEW_AUDIT_LOG)`, paginated,
  returns `chain_valid`).
- `auth/routes.py`: login success/failure logging, 2FA enroll/disable
  (the pre-existing `# Phase 5:` markers), and 2FA login success/failure
  (wrapped the existing `_check_totp_code()` call in a minimal
  try/except so only `/2fa/login`, not `/backup-codes` or `/disable`,
  logs an `mfa_login_failure`).
- `auth/admin_routes.py`: `member_add`, `role_change`, `2fa_reset` at
  their pre-existing markers.
- **Design decision made, not yet confirmed with the requester:** a
  login failure with a completely unknown email has no org to attribute
  the attempt to (the whole log is per-org), so `log_event` is simply
  not called for that specific case -- only "wrong password for a real
  account" logs `login_failure`, using the attempted email as `target`,
  never a `user_id`.

**Done in this pass (items 1-4 from the old list here):**

1. `auth/test_activity_log.py`: chain integrity after several events
   (login/upload/evaluate/confirm); login success/failure logging,
   including a dedicated test for the unknown-email-is-not-logged design
   decision; tamper detection (`verify_activity_chain` goes `false` after
   a row is hand-edited in the DB, both via `GET /audit`'s `chain_valid`
   and by calling the function directly); org isolation (org_alpha and
   org_beta have independent chains, tampering one doesn't affect the
   other, and entries/actors never cross); the permission matrix
   (viewer/engineer 403, senior/admin 200, anonymous 401) plus an explicit
   own-org-scoping test; pagination (`limit`, `before_id`, `has_more`,
   `next_before_id`, clamping); and that a broken logger does not block
   the action it's logging -- `log_event()`'s own try/except never lets an
   exception escape, so the tests monkeypatch `_compute_hash`/`_last_hash`
   (the things *inside* `log_event`) to raise, then confirm upload/evaluate
   still return 200, and a separate test confirms `log_event()` itself
   returns `False` rather than raising.
2. `docs/auth_decisions.md`: new "## 11. Activity log (Phase 5)" section
   (shared hash function with `review_system`, the no-actor-on-failed-login
   case, the unknown-email design decision, the never-blocks-the-action
   guarantee, what's wired where), plus a `GET /audit` entry in the API
   contract (section 9) with its request/response shape.
3. Frontend page: `src/frontend/admin/activity/index.html`, mirroring
   `admin/users/index.html`'s shell (head, sidebar, footer) exactly. Table
   of entries (timestamp, actor, event_type, target), a chain-valid/
   TAMPERED badge, "Load more" using `next_before_id`. Gated the same way
   `admin/users/index.html` gates on `manage_users` -- here on
   `userCan(me, "view_audit_log")` -- with the loading indicator hidden and
   a page-error shown for viewer/engineer instead of the table.
4. `shared.js`: added `renderAuditNav()`, a sibling to `renderAdminNav()`
   (not an extension of it -- `senior_engineer` gets the audit link but not
   Team), called from `initAuth()`'s `render()`. Added an `activityLog({limit,
   beforeId})` fetch helper next to `adminListUsers()`. Normalized the
   file back to consistent CRLF line endings (matching its prior state) --
   the edit itself would otherwise have landed as LF and mixed the file.

**Still to do (was step 5):** run `cd src/backend && pytest auth/ -q` for
real once this reaches an environment with network/pytest, and click
through the new Activity log page once in a browser (load, paginate with
Load more, and -- to see the TAMPERED state -- hand-edit a row in
`memory.db` and reload). Once both check out, this Phase 5 entry can move
to "done" the same way Phase 3/4's entries above do.

- **Phase 6 (hardening + demo prep):** tighten CORS from `"*"`; consider
  a relative `API_BASE` instead of the hardcoded
  `http://localhost:8000` in `shared.js`; decide whether
  `report_generator/router.py` (currently unmounted, unauthenticated)
  stays unmounted or gets auth; consider a session-listing endpoint so a
  viewer can actually open reports; write the final known-gaps list for the
  submission.

## Conventions (unchanged, still apply)

Auth logic stays in `src/backend/auth/`. Tests for every phase go in
`src/backend/auth/test_*.py`, sharing `auth/conftest.py`'s fixtures.
Update `docs/auth_decisions.md` whenever a decision changes -- done for
this pass. Run tests with `cd src/backend && pytest auth/ -q`.

Note on line endings: despite the original convention note about CRLF,
the actual files under `src/backend/auth/` and this project's Python
generally use plain LF already (only a handful of root-level files like
`requirements.txt` and `api.py` are CRLF) -- new and edited files in
this pass matched whatever their existing siblings used, which was LF
for everything touched.
