# Legacy / unused files

`app.py` and `frontend/app.js` were an earlier, parallel attempt at wiring
the frontend to a backend. They were moved here (out of the active app)
because they were broken and incompatible with the current frontend:

- `app.py` exposes a completely different API contract
  (`/api/scans/...`, scan-based) than the one the actual pages call
  (`/upload`, `/confirm`, `/evaluate/{id}`, `/report/{id}/pdf`, session-based,
  defined in `../api.py` and called from `../frontend/shared.js`).
- `app.py`'s `SCREEN_FILES` map and `app.js`'s `SCREENS` map both point at
  old filenames like `"upload_configuration/code 4 uc.html"`, which don't
  exist anymore — the pages were renamed to `index.html` at some point and
  these two files were never updated to match.
- `app.js` was still `<script src="../app.js">`-included at the bottom of
  `frontend/review_unknown_lines/index.html`, even though that page already
  has its own working inline `<script>` that does the same job against the
  real API. Having both loaded meant two competing click handlers on the
  same "Confirm All" button. That include has been removed.

**The working app is:** `../api.py` (backend) + `../frontend/shared.js` +
the inline `<script>` block already in each `frontend/*/index.html` page.
That combination was tested end-to-end (upload → vendor detection → review
→ evaluate → PDF report) and works.

These two files are kept here for reference only. Nothing else in the
project imports or references them. Safe to delete if you don't need them.
