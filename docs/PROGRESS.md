# Execution ledger: 2026-10-29-sentinel-lab.md

Latest analysis-alerts continuation: global clickable file/URL/IP/hash updates, active counts, owner-only status feed, completion/attention alerts and pending-page result links are implemented. 76 focused Python and 21 client tests passed. Review findings for keyboard focus and cross-tab read state were reproduced and fixed. Live read-only feed/result-link checks passed without provider submissions; browser visual/click-through testing remains unavailable. See VERIFICATION.md and superpowers/plans/2026-11-02-analysis-alerts.md.

Latest document-progress continuation: Protect and Recover have an animated processing bar with a matching server-confirmed Download started state, duplicate-click protection and bounded waiting. Native attachments remain intact. 63 focused Python tests and 7 JavaScript checks passed, plus live Docker exact-byte recovery with progress markers. Independent review found no material issues. Browser visual/cookie-observation verification is unavailable because the control tool cannot initialize. See VERIFICATION.md and superpowers/plans/2026-11-02-document-progress.md.

Latest upload fix: corrected false multipart 413 errors and aligned the total upload cap with advertised document/image sizes. Added client file-size feedback and Flask document-form recovery guidance. 93 focused regressions passed; the live server returned a protected PNG and exact original bytes on Docker recovery. Client validation logic passed separately; browser retesting was blocked by a tool initialization error. See VERIFICATION.md and superpowers/plans/2026-11-02-upload-limits-fix.md.

Latest key-view continuation: owner public PEM display/copy/download and verified encrypted private PEM viewing are implemented. Native key/document downloads and exact live Docker recovery passed browser/HTTP acceptance. Full suite: 164 passed in 362.00s (0:06:02); exit 0. See VERIFICATION.md and superpowers/plans/2026-11-01-key-view-download.md.

Latest account/admin continuation: automatic encrypted account keys, owner exports/assigned-key document workflows and the guarded account/activity backend are implemented. 154 passed in 262.13s (0:04:22). Real Docker export/recovery, live migration and browser admin/MFA acceptance passed. The independent review finding was fixed with four failing-then-passing concurrency tests. See VERIFICATION.md and superpowers/plans/2026-10-31-admin-account-keys.md. Real customer administrator enrollment, free C: disk space and customer operational/security acceptance remain. Earlier entries below are historical.

Latest continuation: see superpowers/plans/2026-10-31-local-workers.md and VERIFICATION.md. A dedicated Ubuntu WSL 2 / Docker Engine runtime is installed on D:. Real isolated PE inspection and encrypted-document protection/recovery pass acceptance. Local OpenBin has a responsive web page and explicit WSL transport; actual Ghidra decompilation produced code from the inert fixture and the complete worker acceptance command passed. Browser evidence is tracked in VERIFICATION.md. The latest full application suite has **122 passing tests**. The earlier separate hash/URL/IP/file workspace and schema-3 data remain preserved. Automatic AI analysis, customer MFA and independent customer acceptance are still separate work. Older entries below describe earlier builds.

- Plan and source requirements read; no existing application to migrate.
- Ruling: supervised OpenBin import is the proposal's allowed fallback; no undocumented REST interface or fabricated model output.
- Ruling: trusted-server crypto for the local FYP; secrets stay in request memory. A hostile server is outside this model.
- Ruling: MySQL supported through SQLAlchemy; SQLite starts the local demo without a database installation.
- Ruling: build in a new subdirectory because the surrounding repository has no HEAD and contains unrelated files.
- Ruling: no direct OpenAI API integration; OpenBin model setup belongs to the external supervised workflow.
- Pre-flight: factory/models feed routes; crypto returns PNG/tuple; parser returns JSON; reports consume saved scan results. No interface conflicts.

- Tasks 1-4 implemented: accounts/authorization, encryption/recovery, static PE parsing, provider adapter, supervised evidence import, PDF reports and responsive product UI.
- Initial tests failed on missing application modules; implementation brought the initial 29 cases to green.
- Independent review found three material issues: oversized encoded PNGs could be unrecoverable, RSA wrapped-length validation rejected supported intermediate key sizes, and MySQL FLOAT lost provider-quota timing precision.
- Added regressions and observed the three failures before fixing output limits, wrapped-length ranges and BIGINT timestamp storage.
- Browser registration exposed a CSRF lifetime type mismatch. A valid-token regression reproduced the error; numeric seconds fixed it.
- Final Python suite: 34 passed in 32.26 seconds, 30 October 2026. Compilation passed.
- Browser flows verified: account creation, synthetic PE scan, PDF download, image capacity, protection/recovery downloads, key ZIP download, search, mobile navigation and layout.
- Ruling: native attachment form submissions replace JavaScript blob downloads because the embedded browser did not reliably save blob URLs. All three native crypto downloads emitted confirmed download events.
- Mobile history overflow fixed by containing the visually hidden table header within its scroll container.
- Task 5 documentation and source packaging completed. The /keys workflow provides key generation; a second command-line key generator is unnecessary.
- MySQL/Docker and live external providers were not exercised. No accuracy evaluation or production-security claim is made.
- Interface refresh: new shared navy/light theme, readable forms, three dashboard actions, real recent activity and improved responsive layouts. Existing targeted template/workflow checks passed; desktop/mobile browser review completed. See VERIFICATION.md for scope.
