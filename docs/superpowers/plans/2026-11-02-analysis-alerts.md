# Analysis alerts implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this scoped follow-up.

**Goal:** Provide clickable in-app analysis updates for file, URL, IP and hash checks, including in-progress, report-ready, unknown and failure states from any authenticated page.

**Architecture:** Add an owner-only, read-only feed derived from existing ExternalCheck records. An accessible top-bar panel polls local status while the page is visible and renders links to the existing owner-protected results. A small per-account/version browser record stores only record IDs, revision strings and read flags to suppress repeat alerts across page navigation. No provider calls, desktop notifications, new database schema or analysis changes.

**Spec:** The user's current request and screenshot of an in-progress VirusTotal result. Prior authorization to proceed without design questions persists. This small feature's design is recorded here.

## Decisions and constraints

- Use existing server jobs; the feed never submits or refreshes provider work. Do not label unknown/failed/unfinished results as completed successful analysis.
- Return up to 20 active and 20 recent terminal records, plus the currently viewed check when necessary; include the total active count and a link to full history. Return owner identity/version for rejecting results after account switching.
- Each item includes kind, short target label, state, meaningful status label, update revision and an internal result URL. No engine output, private keys or other users' metadata.
- Poll every 10 seconds when visible, pause while hidden, use a request timeout and single in-flight fetch, and stop on authentication expiry/account mismatch. These background requests must not extend the 30-minute idle session.
- The initial snapshot populates the panel without flooding the screen with old toasts. Later new terminal revisions produce clickable alerts; recent unread revisions remain available across navigation. IDs/read flags are capped at 100 entries in localStorage, namespaced by account/security version; indicators and results are never persisted in browser storage. Storage failure falls back to in-memory behavior.
- On a pending detail page, a terminal update replaces the waiting message and badge with a clickable View result link. No forced navigation while users are filling out other forms. Remove the old two-minute detail polling limit for external checks; other scan polling stays unchanged.
- Native Protect/Recover progress remains unchanged. Render provider text with textContent, use internal URLs only, support keyboard open/close, Escape, reduced motion and narrow screens. Errors show reconnecting/session-expired guidance, never false completion.
- Continue in the current project (no Git HEAD), preserve the source ZIP baseline. No unrelated worktree, dependency or hosting changes.

## Work

- [x] Reproduce missing feed/ownership/status/session behavior in Python tests; add failing client-state tests.
- [x] Implement the feed, background-session handling, top-bar panel, clickable completion alerts and pending-page update.
- [x] Run focused external-analysis, account/security and template tests plus Node client tests. Attempt browser inspection and verify local HTTP behavior without spending provider quota or changing real check statuses.
- [x] Obtain one fresh final review, address material findings, update docs, restart the verified local server and refresh the source package; run integrity/privacy checks immediately after this documentation update.

## Ledger

- Pre-flight: existing ExternalCheck.updated_at changes on worker results; revision combines state and timestamp, so refresh back to queued and later completion are distinct. Existing auto-polling touches last_seen on every request; the new endpoint must explicitly avoid that while still enforcing expiry.
- Ruling: in-app alerts and browser-local read flags match this request without introducing migrations or external notification permissions. They work while a signed-in page is open; events while away remain in the recent list/history.
- RED: six Python regressions failed in 11.59s, and six client-state tests failed before implementation.
- GREEN: 76 Python tests passed in 78.22s (0:01:18), exit 0; external-provider flows, upload/document progress and session/security checks included. Evidence: artifacts/qa/analysis-updates-green.txt and analysis-updates-green-exit.txt.
- Independent review identified focus loss during background renders and non-monotonic read flags across tabs. Three new client tests failed before fixes. Unchanged lists retain their nodes, changed lists restore the focused check, and matching-revision read flags merge monotonically with stale-snapshot repair. Final Node suite: 21 passed, exit 0, including existing document progress tests.
- Live read-only HTTP acceptance passed: owner-only no-store feed, all returned result links, four page integrations, assets and signed-out denial. No provider submissions or real record mutations were made. The first attempt ran before the listener was ready and failed with connection refused; after startup was confirmed, the rerun passed. Evidence: analysis-updates-live.txt, analysis-updates-live-exit.txt, and preserved analysis-updates-startup-attempt.txt under artifacts/qa.
- Browser limitation: cua_repl still fails during kernel-assets initialization with path-not-found (os error 3), before page access. Client tests use DOM/fetch/timer stubs; visual browser layout, actual notification clicks and live browser polling are not claimed as verified.
