# Auth decisions (Phase 0)

Locked before any auth code is written. The values live in `src/backend/auth/config.py`; this file explains why. Change a decision here and in `config.py` together, and `auth/test_config.py` will catch most inconsistencies.

## 1. Session mechanism: JWT

Stateless signed tokens via `pyjwt`, algorithm HS256, signed with `JWT_SECRET` from `.env`. Access tokens last 60 minutes, and there is no refresh token: after an hour the user logs in again, which is acceptable for a demo and removes a whole class of bugs. The tradeoff is that a token can't be revoked before it expires, so role changes are read from the database on each request instead of trusted from the token (see decision 3).

Every token carries a `type` claim. Only `access` tokens are accepted by protected endpoints. The short-lived (5 minute) `mfa_pending` token issued between the password step and the TOTP step is accepted only by `POST /auth/2fa/login`, so the second factor can't be skipped.

## 2. Password hashing: argon2

`argon2-cffi` with its default parameters. Not `passlib`, which is unmaintained and breaks with recent `bcrypt` releases. Raw passwords are never stored, logged, or returned.

## 3. Roles

| Role | Can do | Review vote weight |
|---|---|---|
| admin | everything, including managing users in its own org | 3 |
| senior_engineer | upload, confirm, evaluate, view reports, view audit log | 3 |
| engineer | upload, confirm, evaluate, view reports | 2 |
| viewer | view reports only | cannot vote |

This merges the existing review roles into one system instead of running two. The old `user` role (weight 1) is removed; its place is taken by `viewer`. The consensus rule in `review_system.py` is unchanged (6 points from at least 2 reviewers), so no single person, admin included, can promote a line alone.

Endpoints check permissions, not role names, so moving a capability between roles is a one-line change in `ROLE_PERMISSIONS`.

The role in the database is the source of truth. The JWT contains the role for the frontend's convenience (showing or hiding buttons), but the backend re-reads it, so demoting someone takes effect on their next request.

Signup always creates a new org, and the person signing up becomes its admin. There is no way to sign yourself into an existing org, because that would let anyone read another company's reports. People join an existing org only when its admin adds them (Phase 4), as `viewer` unless the admin picks another role.

## 4. Tenancy

A tenant is one `org_id` string on the user. Sessions, learned lines, review votes, and both audit logs are stamped with it. `org_id` always comes from the token, never from a request body or query string.

Learned-line memory is per org. The confirmed lines contain real configuration text (addresses, hostnames, sometimes SNMP communities), so sharing them across customers would leak data. Each org's audit hash chain is also separate.

Requests for another org's session get the same `404` as a session that doesn't exist, so responses don't reveal which session IDs are real.

How it's enforced (Phase 2):

- Every session is stamped with `org_id` and `owner_id` at upload. Every endpoint that takes a `session_id` fetches it through `_get_session_for(session_id, user)` in `api.py`, the single place ownership is checked. Any member of the uploader's org can use the session; teammates review each other's scans.
- `confirmed_lines` is keyed by `(org_id, normalized_line)`, and `memory.py` requires `org_id` on every call, so a forgotten org fails loudly instead of falling back to a global lookup. Scripts that don't pass an org (`test_classifier.py`, running `pipeline.py` directly) skip memory entirely.
- Review votes only combine within one org. `review_system` also refuses a vote from a user outside the org it's cast into.
- Each org has its own audit hash chain. Moving an entry between orgs breaks both chains.
- `auth/test_tenant_isolation.py` includes a test that fails if a new `{session_id}` route is added without an isolation test.

Migration of pre-Phase-2 data is automatic: learned lines and the promotion audit trail move into `org_alpha` (the chain stays valid), and pending votes from the old hardcoded reviewers are dropped so ghost votes can't count toward a promotion.

## 5. Brute-force protection

5 failed attempts (password or TOTP) lock the account for 5 minutes. The counter is in memory, which is fine because a restart only resets lockouts.

## 6. 2FA (Phase 3, backend implemented)

TOTP (`pyotp`), issuer name `ConfigGuard`, accepting one 30-second step of clock drift (`TOTP_VALID_WINDOW`). Enrollment isn't active until the user enters a correct first code (`POST /auth/2fa/setup` stores the secret with `totp_enabled = 0`; `POST /auth/2fa/verify` is what flips it on). Calling `/setup` again before `/verify` replaces the unconfirmed secret; after enrollment it returns `409`. 8 single-use backup codes are generated at enrollment and stored hashed. The QR code is returned as a PNG data URI (`qrcode`), so it works on the static frontend pages with no image files on disk.

**Password required for setup and disable.** A stolen access token alone must not be enough to turn 2FA on (an attacker could enroll their own phone and lock the real owner out) or off. `/setup` and `/disable` both re-check the password against `lockout.py`'s normal per-email bucket -- the same one `/auth/login` uses.

**Replay protection.** `users.totp_last_step` stores the last 30-second time step that was successfully used. `totp.verify_code()` only accepts a step strictly greater than that, so a shoulder-surfed code can't be reused even inside its own 30-second window. `store.record_totp_step()` is an atomic compare-and-set (`WHERE totp_last_step < ?`) and returns whether it advanced; `routes._check_totp_code` rejects the login when it returns `False`, so two concurrent requests with the same code can't both succeed. Confirming enrollment (`/2fa/verify`) deliberately does **not** record a step: otherwise the code the user just typed would be rejected as a replay if they signed in (or regenerated backup codes) within the same 30 seconds. Replay protection starts with the first real login.

**Backup codes.** 10 characters from an unambiguous alphabet (no `0/O`, `1/l/I`), shown as `xxxxx-xxxxx`, hashed with SHA-256 (not argon2 -- these are ~50 bits of random entropy, not a human-chosen password, so a fast hash is safe and lets the server find a code with one indexed lookup instead of 8 argon2 checks). Regenerating (`POST /auth/2fa/backup-codes`) deletes and replaces all of them. Format-checking (`totp.normalize_backup_code`) is forgiving of case, dashes and stray spaces.

**Brute-force limits.** TOTP and backup-code checks share one `lockout.py` bucket per user, keyed `mfa:<user_id>`, separate from the password bucket -- a correct password followed by 5 wrong codes locks only the code step.

**Half-logged-in token.** `POST /auth/login` returns `{"status": "mfa_required", "mfa_token": ...}` when `totp_enabled` is true, instead of the normal response. The token is a JWT with `type: "mfa_pending"`, 5-minute lifetime (`MFA_PENDING_TOKEN_MINUTES`), and `get_current_user` already rejects it everywhere except `POST /auth/2fa/login` (it only accepts `type: "access"`). To make it single-use, `routes.py` keeps an in-memory dict of spent `jti` claims (pruned once their token would have expired anyway); a second attempt with the same token returns `401` even if it hasn't expired. The token is spent only when the code is **correct**: a typo returns `401 Incorrect code.` and the same token can be used again, so the user doesn't have to re-enter their password (the login page relies on this). Guessing is bounded by the `mfa:<user_id>` lockout bucket instead. Like `lockout.py`, this set is in-memory by design -- a restart just means any in-flight `mfa_pending` token must be reissued by signing in again.

**Known gap: secret storage.** `totp_secret` is stored in plaintext in SQLite (`users.totp_secret`) because the server has to read it back to check codes. A real product would encrypt it at rest with a separate key (e.g. Fernet). Not done for the hackathon.

Frontend for all of this is built: the login page's second step (`src/frontend/auth/login/index.html`) and the Security settings page (`src/frontend/account/security/index.html`), reachable from the user-chip menu in `shared.js`. See PROGRESS.md at the project root for what's still unverified (the test suite has not been run in this build environment) and what Phase 4 onward still needs.

## 7. Demo data

Two orgs so isolation can be shown live: `org_alpha` and `org_beta`, each with one account per role. All demo accounts share `DEMO_PASSWORD` from `.env`. Emails follow `<role>@<org>.demo`: `admin@alpha.demo`, `senior@alpha.demo`, `engineer@alpha.demo`, `viewer@alpha.demo`, and the same four at `beta.demo`.

Migration is automatic: on startup, an old-style `users` table (the alice/bob/carol demo reviewers) is detected and replaced. Learned lines in `confirmed_lines` are kept. Nobody needs to delete `memory.db`.

## 8. Frontend conventions

The token is kept in `localStorage` under the key `cg_token`. This is readable by any script on the page, so an XSS bug would expose it; accepted for the hackathon and listed as a known gap.

All API calls go through one `authFetch()` in `shared.js`, which attaches `Authorization: Bearer <token>`. A `401` clears the token and redirects to the login page. A `403` shows a "you don't have permission" message and does not log out.

The PDF download changes from `window.open(url)` to `authFetch` followed by a blob download, since a new tab can't send the header.

`confirmed_by` is removed from the `/confirm` request entirely. The server takes the reviewer from the token.

## 9. API contract (so frontend and backend can be built in parallel)

Errors keep FastAPI's shape: `{"detail": "message"}`.

`POST /auth/signup`
request: `{"email": "a@x.com", "password": "...", "name": "Asha", "org_name": "Acme Networks"}`
response `201`: `{"user_id": "...", "email": "a@x.com", "name": "Asha", "org_id": "<generated>", "role": "admin", "totp_enabled": false}`
The server generates `org_id`; the client never sends one.
Password must be at least 10 characters. Duplicate email returns `409`.

`POST /auth/login`
request: `{"email": "a@x.com", "password": "..."}`
response `200` without 2FA: `{"status": "ok", "access_token": "...", "token_type": "bearer", "user": {user object}}`
response `200` with 2FA on: `{"status": "mfa_required", "mfa_token": "..."}`
Wrong credentials return `401` with the same message whether the email exists or not. Locked accounts return `429`.

`POST /auth/2fa/login` (Phase 3)
request: `{"mfa_token": "...", "code": "123456"}` (code may also be a backup code)
response: same as the `"ok"` login response, plus `"backup_codes_remaining"` if a backup code was used.
`401` if the mfa token is expired, invalid or already used, or if the code is wrong. `429` after 5 wrong codes.

`POST /auth/2fa/setup` (Phase 3, requires access token)
request: `{"password": "..."}`
response `200`: `{"secret": "...", "otpauth_uri": "otpauth://...", "qr_code": "data:image/png;base64,..."}`
`401` wrong password. `409` already enabled.

`POST /auth/2fa/verify` (Phase 3, requires access token)
request: `{"code": "123456"}`
response `200`: `{"enabled": true, "backup_codes": ["k7mqp-x2hvn", ... 8 codes]}` -- shown once, never again.
`400` setup was never started. `401` wrong code. `409` already enabled.

`GET /auth/2fa/status` (Phase 3, requires access token)
response: `{"enabled": true, "backup_codes_remaining": 6}`

`POST /auth/2fa/backup-codes` (Phase 3, requires access token)
request: `{"code": "123456"}` (current TOTP code; a backup code does not work here)
response `200`: `{"backup_codes": [...8 new codes]}`. Old codes are all invalidated.

`POST /auth/2fa/disable` (Phase 3, requires access token)
request: `{"password": "...", "code": "123456"}` (code may be a backup code)
response `200`: `{"enabled": false}`

`GET /auth/me`
response: the user object. The frontend calls this on page load to confirm the stored token still works and to learn the role.

The user object is always `{"user_id", "email", "name", "org_id", "role", "totp_enabled"}`.

`GET /audit` (Phase 5, requires `view_audit_log`)
query params: `limit` (default 50, clamped server-side to 200), `before_id` (optional cursor)
response `200`: `{"entries": [{"id", "actor_user_id", "actor_role", "event_type", "target", "detail", "timestamp"}, ...], "has_more": bool, "next_before_id": int | null, "chain_valid": bool}`
Newest first. Pass the previous response's `next_before_id` back in as `before_id` to page further back; `has_more` is `false` and `next_before_id` is `null` on the last page. `chain_valid` is recomputed on every call (see section 11) -- it is not cached, so a tampered row is caught on the very next read. `403` for `engineer`/`viewer`; `401` anonymous.

## Known gaps accepted for the hackathon

Sessions are still an in-memory dict and vanish on restart. No token revocation or refresh. No email verification or password reset. Token in localStorage. Members are added directly by an admin with a password the admin sets; a real product would send email invites. TOTP secrets are stored in plaintext (section 6). Spent `mfa_pending` JWT ids are tracked in memory (pruned on expiry, lost on restart), same category as the sessions dict.

## 10. Roles are enforced (Phase 4)

Every endpoint declares the permission it needs with `require_permission(Permission.X)` (`auth/deps.py`), which runs `get_current_user` first and then checks the role read from the database. Anonymous callers get `401`; a signed-in caller whose role lacks the permission gets `403` **before** the endpoint looks anything up, so a forbidden caller can't probe which session ids exist.

| Endpoint | Permission |
|---|---|
| `POST /upload` | `upload` |
| `POST /confirm` | `confirm` |
| `POST /evaluate/{session_id}` | `evaluate` |
| `GET /report/{session_id}/pdf`, `GET /review/report` | `view_reports` |
| `/admin/*` | `manage_users` |
| `/auth/me`, `/auth/2fa/*` (except login) | any signed-in user (own account) |

`auth/test_rbac.py` fails if a route is added without a permission and without being listed in its `OPEN_ROUTES`. Note that `viewer` currently has no way to *list* sessions, so it can only read the review report and download a PDF for a session id it is given; a session-listing endpoint is a Phase 5/6 candidate.

### Admin endpoints (all need `manage_users`, all scoped to the caller's own org)

`GET /admin/users` -> `{"users": [user object, ...]}`

`POST /admin/users` request: `{"email", "name", "password", "role"}` (`role` defaults to `viewer`; password 10+ characters). Response `201`: the user object. `409` duplicate email (emails are unique across all orgs), `422` validation. The org is always the admin's; a client-sent `org_id` is ignored.

`PATCH /admin/users/{user_id}/role` request: `{"role": "engineer"}`. `404` for a user in another org (same as a nonexistent id), `409` if it would leave the org with no admin. Takes effect on that user's next request (decision 3).

`POST /admin/users/{user_id}/reset-2fa`: turns off 2FA and deletes the member's backup codes so they can sign in with their password and enrol again. `400` if `user_id` is the caller's own (use `/auth/2fa/disable`, which asks for the password and a code, so a stolen admin token can't strip the admin's own second factor). `404` for another org's user.

Other input limits added alongside: `/upload` accepts at most 20 files of 10 MB each (`413` / a per-file error), `/confirm` rejects fields that aren't in `NormalizedConfig` (or `unclear`), and `/evaluate` returns `400` for an unknown framework instead of silently evaluating nothing. Review votes only count together when they agree on the same field **and** value.

## 11. Activity log (Phase 5)

A second, separate hash chain from `review_system.py`'s (which only records line-promotion votes): `activity_log.py` records general activity -- logins, uploads, confirmations, evaluations, PDF downloads, 2FA and admin actions -- one chain per `org_id`, in a new `activity_log` table (`id, org_id, actor_user_id, actor_role, event_type, target, detail, timestamp, prev_hash, entry_hash`).

**Same hash function, on purpose.** `entry_hash` is computed with `block2b.review_system._compute_hash`, imported rather than reimplemented, so this chain hashes identically to the review-promotion chain and the two can never drift apart if that function is ever changed. The two tables are still never to be confused: this one is "what did anyone in this org do", the other is "which lines has the org's review process promoted".

**Chaining.** Each org's first row links to the literal string `"GENESIS"`. Every later row's `prev_hash` is the previous row's `entry_hash`, and `entry_hash` covers `prev_hash` plus a `sort_keys=True` JSON dump of the row's other fields -- the same scheme decision 4 already uses for the review chain, for the same reason: re-walking the chain in `id` order and recomputing every hash (`verify_activity_chain`) catches a row edited after the fact, whether the edit is to `target`, `detail`, `actor_role`, or anything else in the payload.

**No actor for a failed login.** `log_event(user, event_type, ...)` is the normal call -- `org_id`, `actor_user_id` and `actor_role` all come from the authenticated `user`, and an `org_id` passed alongside `user` is ignored, so a caller can never log into an org other than its own. The one exception is a failed login: nobody is authenticated yet, so `log_event(None, "login_failure", target=email, org_id=...)` leaves `actor_user_id`/`actor_role` `NULL` rather than guessing -- naming a user_id for an attempt that was never authenticated as that user would be misleading. **Design decision:** if the attempted email doesn't match any account at all, there is no org to attribute the attempt to (the whole log is per-org by design), so that case is not logged anywhere -- not into a shared/global bucket, not skipped silently in a way that drops data that belongs somewhere. Only "wrong password for a real account" logs `login_failure`.

**Never blocks the action it watches.** `log_event()` never raises: any failure while writing (a locked database, whatever) is caught, reported to the `activity_log` logger, and the caller's request proceeds as if nothing happened -- an audit trail must not become a second way for a legitimate action to fail. It returns `True`/`False` so tests can tell the two cases apart; callers in `api.py` and `auth/` don't check the return value.

**Where it's wired in:** `api.py` startup calls `activity_log.init_activity_log_table()` (after `auth.store.init_auth_tables()`, since `activity_log.org_id` references the `orgs` table). Logged events: `upload` (per file; `upload_rejected` for the two rejection paths -- too large, not UTF-8), `confirm` (per confirmed item), `evaluate`, `report_pdf_download`, `login_success`, `login_failure`, `mfa_login_success`, `mfa_login_failure`, `2fa_enroll`, `2fa_disable`, `member_add`, `role_change`, `2fa_reset`.

**Reading it back:** `GET /audit` (see section 9), gated on the new `view_audit_log` permission (already granted to `senior_engineer` and `admin` in the section 3 table). Paginated newest-first with a `before_id` cursor, same shape as any other list endpoint in this API, plus `chain_valid` recomputed on every call.
