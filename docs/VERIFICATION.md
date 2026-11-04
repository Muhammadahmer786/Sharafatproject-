# Verification record

## Automatic Windows client setup — 4 November 2026

- **27 installer regression tests passed** (`tests/test_client_setup.py`, 6.61s): first-use configuration, original-secret preservation, interrupted checkpoints/virtual environments, exact locked dependency verification, account/API preservation, stop-before-account-creation on worker failure, C: opt-in, WSL registry ownership and global/per-distro configuration preservation, cache quarantine and verified publication, and redirect rejection on a real loopback test server. Windows/network installation boundaries use substitutes and temporary fixtures; these tests do not install host runtimes.
- **16 related tests passed** (10.69s): worker downloads, WSL worker transport, installed AI runtime supervision and web-server cleanup. **33 JavaScript tests passed** across document progress, analysis notifications and AI UI.
- Actual Windows CMD launcher smoke test passed from a path containing spaces and an apostrophe. It invoked a deliberately harmless PowerShell stub and forwarded its successful exit. Both new PowerShell scripts parsed without syntax errors. The Python `--plan`/`--help` entry points ran without installing anything. Documentation links/anchors and current lock-file versions were checked.
- Independent source review found four recovery gaps: a venv with Python but missing pip, incomplete locked-package checks, overwritten per-distro WSL configuration, and corrupt Ubuntu/Ollama archives preventing reruns. Regression tests reproduced the gaps before fixes; the final focused tests above pass.
- The complete Python suite was attempted repeatedly, but long tool sessions disconnected before returning a result. No complete full-suite pass is claimed for this change. The focused results above are the available fresh evidence.
- No clean client Windows installation, real UAC/reboot sequence, multi-GB download or newly installed engine/model was performed during this change. The existing workstation/application configuration and credentials were not replaced. A fresh client installation still requires the documented acceptance checklist; administrator authenticator enrollment and the client's own provider access remain personal/operator steps.

## Automatic local OpenBin AI triage — 2 November 2026

Full regression suite: **263 passed in 658.26s**, exit 0 (`artifacts/qa/local-ai-full.txt`). The final shutdown/submission race test was added afterward; **13 focused lifecycle/evaluation tests passed in 22.82s**, including that new case. Client suites: **33 tests passed** across document progress, analysis-update state/UI and local-AI UI. The earlier focused adapter/routes/migration suite passed 87 tests before review fixes.

The subsequent runtime supervisor and server cleanup changes passed **26 focused runtime/lifecycle/job/route tests in 45.14s**. Four regression cases first failed against the previous code, then passed after serializing runtime ownership with shutdown and covering partial startup with `ExitStack`. Independent review confirmed those fixes. The request-limit server test was isolated from the installed model service and passed separately (**1 passed in 3.42s**). These focused checks extend the earlier full run; the complete suite was not rerun after the runtime-only changes.

- Real standalone acceptance ran `tools/check_local_ai.py` against the bundled inert 1 KiB PE: isolated PE inspection → real OpenBin/Ghidra extraction → real local Qwen3 inference → validated report. It selected the one available function, with no truncation or decompilation skips. Result `no_indicators` applies only to this selected evidence. No uploaded program was executed. The test took **361.48 seconds** under concurrent regression load; this is a plumbing check, not malware-detection accuracy. Evidence: `artifacts/qa/local-ai-real-report.json` and runtime QA logs on D:.
- Installed official Ollama 0.40.13 portable runtime after SHA-256 verification. Qwen3:4b digest: `359d7dd4bcdab3d86b87d73ac27966f4dbb9f5efdfcc75d34a8764a09474fae7`. Runtime/model assets are on D:. Local API binds loopback; cloud is disabled, and adapter tests reject remote endpoints/models, redirects, oversized responses, tool calls, missing evidence, invalid citations and incomplete results.
- Actual browser acceptance on the updated site: signed in; uploaded the inert fixture; observed the real inspecting/decompiling milestones; left the job page; received **AI analysis complete**; clicked the toast to open its saved report. Both **PDF** and **JSON** links emitted browser download events. The report identifies local inference, model digest, selected coverage and limitations. Its owner-private record remains available at `/ai/dd69fe79-a9b0-4111-96d3-1bc0c850489f`. Desktop and 390-pixel mobile upload layouts were visually inspected, and the temporary viewport was reset.
- Schema 5 migration created a pre-upgrade backup. Read-only comparison verified every previous user/scan/external-check/account-key ID survived (1/2/7/1 records respectively), and SQLite integrity passed. Restore tests cover schema 2, 3 and 4 upgrades plus current backups. No private configuration or original upload bytes are packaged.
- Independent backend review found shutdown terminal-state and orphan-process issues. Failing regressions preceded fixes: mark shutdown work interrupted, guard submission/shutdown under one lock, monitor parent-process death, and clean only job-named containers. Final review found no further actionable backend issue. UI review caught missing cancelled/interrupted notifications; a failing state transition test preceded the fix, with truthful labels preserved.
- Evaluation harness tests verify unique sample hashes, required independent labels/provenance, abstentions/failures and explicit metric denominators. No representative labeled malware dataset was supplied, so no measured accuracy claim is made. The BINNY interactive/cloud-authenticated CLI was not invoked; reports identify OpenBin Ghidra plus constrained local Ollama review.
- Live managed-runtime recovery: confirmed zero queued/running AI jobs, stopped only the Ollama process owned by the site, and verified the model returned in **5.88 seconds**. Browser inspection afterward showed **Local model available** and the preserved completed report. Final doctor passed schema 5, file isolation, local OpenBin, local AI, closed registration and current backup; it correctly returned exit 1 because no administrator with MFA is enrolled. Evidence: `artifacts/qa/local-ai-recovery.json` and `artifacts/qa/local-ai-final-doctor.json`.
- This handover runs the site in a persistent local terminal. A detached launcher experiment did not reliably survive the automation host's process lifecycle and was removed. Use the documented direct Python command or PowerShell 7 supervisor with its terminal open; automatic Windows startup is not configured.

The local server runs with the new feature. CPU analysis is slow on this i7/16 GB workstation; larger evidence can reach the bounded timeout. C: still has only about 0.2 GiB free, so customer use requires disk-space remediation and workload/security acceptance. The source baseline is preserved as `artifacts/Sentinel-Lab-Before-Local-AI.zip`.

## Clickable analysis alerts — 2 November 2026

Focused Python suite: **76 passed in 78.22s (0:01:18)**, exit 0. Evidence: artifacts/qa/analysis-updates-green.txt and analysis-updates-green-exit.txt. Six new Python and six client-state cases were observed failing before implementation.

- An authenticated top-bar Updates panel lists the owner's active and recent VirusTotal file, URL, IP and hash checks. Completion/attention alerts and list entries link to the existing owner-protected result page. Unknown reports, failed checks and unfinished analysis are not labeled successful completed reports. Pending detail pages receive a result link without forced navigation.
- The bounded read-only local feed returns no engine results or other users' data and performs no provider requests. Polls do not extend idle sessions. The client pauses when hidden, limits itself to one request at a time, retries temporary failures and stops/clears visible results on authentication expiry or account/version mismatch.
- **21 Node tests passed**, covering notification revisions/read state, literal rendering of targets, internal-only links, pending-to-terminal updates, storage failure, visibility/session handling, connection errors, keyboard controls and existing document progress. These execute actual client code with DOM/fetch/timer stubs. Syntax checks also passed.
- Independent review found two P2 issues: background renders lost focus and concurrent tabs could restore unread flags. Three failing regressions preceded fixes for preserving/restoring focus and monotonically merging same-revision read flags, including repair of stale shared snapshots. All client tests then passed.
- Live read-only HTTP checks passed after the verified server restart: authenticated no-store feed, all returned owner result links, integration on Protect/Recover/intelligence/history pages, static assets and signed-out denial. No new indicators were submitted and no real check statuses were changed. Evidence: artifacts/qa/analysis-updates-live.txt and analysis-updates-live-exit.txt. A first attempt before listener readiness failed with connection refused; its log is preserved separately as analysis-updates-startup-attempt.txt.
- Browser visual and click-through testing remains unavailable because the browser control tool fails during kernel-assets initialization (os error 3). No browser layout or end-to-end alert claim is made. The source package includes both new client test files and excludes local instance/configuration data.

The feature is active on the local server. Browser-local read status is bounded and account/version scoped; it is not a server-wide notification inbox. The panel shows recent subsets with access to complete history. Existing customer-readiness limitations remain unchanged.

## Document processing progress — 2 November 2026

Focused regression suite: **63 passed in 163.12s (0:02:43)**, exit 0. Evidence: artifacts/qa/document-progress-green.txt and document-progress-green-exit.txt. This covers document progress, upload limits, document workflows, cryptography, assigned keys, private-key viewing and hardening. Before implementation, three new Python checks failed and seven passed. Five initial JavaScript checks failed on the missing controller.

- Protect and Recover now display an accessible, indeterminate progress bar while native upload/processing runs. A fresh per-submission marker links the page to a short-lived route-scoped cookie emitted only with a successful document attachment. The resulting **Download started** state acknowledges the server response, not completion of the browser's disk save. No guessed percentage, new storage, worker changes or extra document upload.
- **7 Node tests passed**, including real client controller and app.js integration with DOM/timer stubs: both modes, unrelated cookies, repeat/duplicate submissions, timeout, page departure, validation-before-progress and fallback if random token generation is unavailable. Syntax and existing upload-size logic checks passed. Reduced-motion CSS is present.
- Real HTTP/Docker acceptance passed on the restarted local server: both forms/assets served; an invalid request emitted no success marker; protected PNG and recovered document attachments carried their own markers with the correct paths; recovery exactly matched the original bytes. Evidence: artifacts/qa/document-progress-live.txt and document-progress-live-exit.txt, exit 0.
- Independent review found no material correctness or security issue. Browser visual rendering and cookie observation remain unverified: the browser tool failed during initialization with a kernel-assets path error before page access. DOM-stub and HTTP checks are not represented as browser end-to-end acceptance.

The local server is running with the change. The source-only package includes the client tests; the preceding source archive is preserved as Sentinel-Lab-Pre-Document-Progress-Source.zip. Existing customer-readiness limitations remain unchanged.

## Protect upload limits — 2 November 2026

Focused regression suite: **93 passed in 148.34s (0:02:28)**, exit 0. Evidence: artifacts/qa/upload-limits-green.txt and upload-limits-green-exit.txt. Before implementation, five new cases failed and five passed. A deterministic valid multipart upload below 200 KB reproduced a false 413 caused by the form parser's working-memory limit equaling its 64 KiB read size.

- Multipart working memory is now bounded at 128 KiB. Flask and Waitress share a 28 MiB body cap, sufficient for the advertised 5 MiB document plus 22 MiB image and key/framing overhead. Individual file limits, 12-million-pixel/capacity checks and the 20-part form bound remain. The combined-size regression mocks processing and proves transport acceptance only.
- The restarted local server passed check-live-upload-limits.py (exit 0): the former small-file failure now produces an image attachment; real Docker assigned-key recovery produces a document attachment with exact original bytes. Settings display the updated limit. Waitress rejects an oversized Content-Length before body upload with HTTP 413.
- Protect/recover inputs expose size limits. Node syntax checking and check-upload-validation.cjs passed actual client validation/event logic for oversized inputs, replacing them with valid files, disabled/re-enabled uploaded keys, the total cap and valid native form submission.
- Flask-generated authenticated document 413s return the document form with limits and reselection guidance. Requests rejected by Waitress before Flask retain the transport server's 413 response. Independent review prompted this distinction and correction of outdated settings text.
- Browser retesting was unavailable: the browser automation tool failed before page access with a kernel-assets path error, including after reset. The client checks above use DOM stubs, not a live browser; no new browser download event or visual verification is claimed. The previous browser acceptance below is historical.

The local server is running with this fix. Source packaging preserves its previous ZIP as Sentinel-Lab-Pre-Upload-Fix-Source.zip and excludes instance data/secrets. Existing customer-readiness limitations remain unchanged.

## Owner key viewer and downloads — 1 November 2026

Final full suite: **164 passed in 362.00s (0:06:02)**, exit 0, using fresh D: temporary storage. Evidence: artifacts/qa/key-view-full.txt and key-view-full-exit.txt. The focused suite passed 32 tests; five missing-view cases failed before implementation.

- Every owner sees their public PEM and can copy/download it. Private viewing requires the existing fresh password, enrolled TOTP and trusted-server checks plus a separate backup passphrase. The same assigned key is re-encrypted for display; its vault copy is unchanged. No private PEM appears on GET, failed verification or another account's request. Viewing is audited separately.
- Live local HTTP/Docker acceptance passed real CSRF rejection, no-store private responses, public/private pair binding, encrypted ZIP backup, native document attachments and exact recovery of the original sample bytes. Script: artifacts/qa/check-live-key-view.py, exit 0.
- The in-app browser verified public/private display, public/private Copied feedback, matching public clipboard text, Hide private key, and actual public PEM, ZIP, protected PNG and recovered-file download events. Desktop and 390px layouts were reviewed; no horizontal page overflow at 390px. Final browser error log was empty. The original tab reached a temporary connection-error page during restart; verification continued in a fresh in-app tab after health returned 200. The five-minute auto-clear implementation was reviewed but not verified by waiting five minutes. Details: artifacts/qa/key-view-acceptance.txt.
- Independent review found no Critical or Important issues. Native download responses are preserved; the notice now directs users to their browser's Downloads panel.

This verifies the requested local key/document workflows. It does not change the remaining customer acceptance, real administrator/MFA setup or optional MySQL limitations below. C: had approximately 110 MiB free during this run and still needs disk-space remediation.

## Administration and automatic account keys — 31 October 2026

Final full regression suite: **154 passed in 262.13s (0:04:22)**, exit 0, using a fresh test directory on D:. Evidence: artifacts/qa/account-admin-data-drive-suite.txt and account-admin-data-drive-suite-exit.txt. An earlier C:-based run passed 151 tests but ended with three database setup errors after SQLite reported `database or disk is full`; that run is not reported as a pass. No user files were removed. C: still needs free-space remediation before customer use.

Implemented and verified:

- Account creation (registration, administrator setup and operator CLI) assigns a unique RSA-3072 pair transactionally. Legacy users receive keys after successful password/MFA sign-in. Assigned private keys remain encrypted under per-account passwords derived from the original server secret.
- Owners export their same assigned public/private pair after fresh password and enrolled TOTP verification, choosing a separate export passphrase. Password changes and recovery preserve the assigned pair. Wrong-owner access, public/private mismatch, changed server secret, duplicate concurrent assignment and failed provisioning are covered.
- All admin routes share role/MFA enforcement. Tests cover account setup-code redemption, access disable/re-enable, revocation, actor/target audit events, search/date/pagination, administrator-account restrictions and exclusion of private scan/indicator/key contents.
- One independent final review found a SQLite writer-lock lifetime problem. Four route regressions first failed with `database is locked`; moving cleanup after key generation and committing successful MFA/assignment before workers made all four pass. The final complete suite above includes them. No Critical or deferred Minor findings remained from that review.
- Schema 3 → 4 live migration created a pre-upgrade backup and preserved one account, one scan, five external checks and 32 audit events. A new verified backup after assignment includes the encrypted vault. Legacy staged restores and preservation/decryption of current-schema vault backups are tested.
- Rebuilt the local document image using cached dependencies. Real Docker acceptance passed key generation, encrypted re-export, static PE inspection and exact document recovery with both the original and exported private keys. Evidence: account-key-docker-acceptance.txt (exit 0).
- A disposable local instance on port 5051 passed headless Edge acceptance with CSRF enabled: real administrator authenticator enrollment, account creation and setup-code redemption, owner key ZIP/public PEM downloads, exact assigned-key document recovery, denial of owner access to administration and administrative session revocation. No JavaScript errors. The test server was stopped. Screenshots of desktop/mobile admin and key pages were inspected; no horizontal page overflow. Evidence: admin-accounts-browser.txt (exit 0), admin-overview-desktop.png, admin-account-mobile.png, assigned-keys-desktop.png and assigned-keys-mobile.png.
- The actual port-5050 server passed health, preview-user legacy assignment, assigned-key protection and exact-byte Docker recovery; the preview account remains an ordinary user. Evidence: live-account-keys.txt (exit 0).

Readiness reports schema 4, both isolated worker images, closed registration and a recent backup. The remaining failed prerequisite is the real administrator/authenticator account. No default administrator was created or preview account promoted. Owner MFA is preserved during password recovery; recovery administrators are nevertheless trusted and can take over a non-MFA account by redeeming a recovery code. Machine operators hold the original vault secret. SQLite is verified; optional MySQL remains unverified. This is not a customer security certification.

## Local processing continuation — 31 October 2026

Latest complete application suite: **122 passed in 76.51 seconds**, exit 0. Evidence on this workstation: artifacts/qa/local-workers-tests.txt and local-workers-tests-exit.txt. New regressions cover explicit WSL selection/no fallback, binary transport, authenticated private OpenBin downloads, worker availability reporting and interrupted/corrupt archive handling. These regressions were observed failing before implementation.

Installed a dedicated Ubuntu 24.04 WSL 2 distribution named SentinelLab under D:\SentinelRuntime, with Docker Engine 29.9.2. Windows was not upgraded or rebooted. The Ubuntu archive matched Microsoft's manifest checksum. The WSL memory limit is 6 GB, two CPUs, swap disabled; no Docker TCP socket is exposed.

Real container checks completed with synthetic inputs:

- Static PE inspection returned the expected SHA-256.
- Docker-generated encrypted private keys, AES-GCM protection/PNG embedding and recovery returned the exact original binary bytes.
- A first cold-start run timed out; measurement showed 14.16 seconds for WSL startup and under one second for subsequent Docker commands. A bounded 30-second startup allowance fixed the real acceptance run without changing parser/container isolation.
- Headless Edge exercised login/CSRF, actual key ZIP download, protection and exact-byte recovery through the web forms. No page JavaScript errors were reported.
- Desktop and 390-pixel mobile OpenBin layouts were inspected from screenshots. No horizontal document overflow; the mobile check waits for the sidebar transition to finish. The embedded browser automation tool failed to initialize, so this check used a fresh headless Edge session.
- The official OpenBin archive downloaded completely and matched its pinned size and SHA-256 before Docker load. Both images built successfully. Actual Ghidra execution initially failed because Java selected `/nonexistent` as the restricted user's home. Setting Java home/temp to the RAM-backed `/tmp` fixed execution while preserving the unprivileged, network-disabled, read-only container.
- The complete real acceptance command `tools/check_workers.py --include-openbin` passed, exit 0: static inspection, key generation, exact document recovery and OpenBin decompilation. The inert fixture produced one function with nonempty decompiled code, matching SHA-256 provenance and `ai_model_ran=false`. Evidence: artifacts/qa/all-worker-acceptance.txt and all-worker-acceptance-exit.txt. The upstream HTTP service healthcheck is disabled for this one-shot worker.
- The final complete headless Edge check passed, exit 0: authenticated desktop/mobile OpenBin layouts, HTTP 200 and a real JSON attachment containing decompiled code/local provenance, key ZIP download, PNG protection and exact-byte recovery. No page JavaScript errors occurred. Evidence: artifacts/qa/local-modules-browser.txt and local-modules-browser-exit.txt; screenshots: openbin-desktop.png and openbin-mobile.png. Earlier browser attempts timed out; the harness now gives both click/navigation actions and download waits enough time for the bounded server operations and reports rejected POST responses immediately. The final successful run used serial operations without concurrent readiness probing.

The original OpenBin archive URL was incorrect; the official release tag is openbin-v0.10.0. A transfer truncated at exactly 200 MiB was rejected by checksum verification. The downloader now resumes 32 MiB HTTP ranges and verifies the complete pinned size and SHA-256 before loading an image.

The latest doctor report confirms schema 3, both local worker images, closed registration and a recent verified backup. It exits 1 because the real administrator/authenticator prerequisite is not complete. Evidence: artifacts/qa/local-worker-readiness.json. A simultaneous browser/doctor run earlier exceeded one 35-second image probe and the browser's default 30-second navigation deadline; the standalone readiness rerun passed both worker probes. The browser check now allows navigation to outlast the documented bounded startup probe. Workstation load/startup acceptance remains required. At final checking C: had approximately 0.70 GiB free and D: 14.56 GiB free; no user files were deleted to free space.

Independent review found no Critical/Important issue in the inspected integration. Deferred minor recovery improvements: a corrupt complete cache file needs manual quarantine; a partially completed WSL/Docker installation needs operator recovery. Real customer administrator MFA, workload/security acceptance and automatic AI/BINNY model integration remain outstanding. No hostile-file security certification or detection-accuracy claim is made.

## External intelligence workspace — historical result, 30 October 2026

**115 passed in 104.25 seconds**, exit 0, from the complete pytest suite after the final provider compatibility fix. Saved local evidence: artifacts/qa/full-tests.txt and full-tests-exit.txt. Python compilation passed. No new Python dependencies were added; the earlier dependency audit below remains the recorded audit.

Implemented and tested MD5/SHA-1/SHA-256 lookup, URL submission, public IPv4/IPv6 reputation, and arbitrary-extension file upload up to 20 MiB. Coverage includes input validation, fixed endpoints/no redirects, explicit disclosure, missing credentials, CSRF, owner access, RAM-only uploads, deletion during response, durable leases, retry/poll budgets, shared quota fairness, schema-2 restore staging, malformed/oversized responses, provider HTTP errors, and bounded credential-scrubbed subprocesses.

One independent read-only review found three Important issues and one Minor issue: expired-lease retry budgets, quota phase-lock starvation, schema-2 backup compatibility, and missing report age. The material issues were reproduced with failing regressions before fixes; timestamps are now shown separately from request time. The same crash-budget protection was applied to the existing PE hash queue. A previously flaky MFA replay test now reuses the same code instead of generating a potentially different code across a time boundary; authentication behavior was unchanged.

Live checks used the privately configured key and the actual loopback UI with CSRF enabled:

- Empty-file SHA-256 lookup: completed, 75 engine outcomes.
- 8.8.8.8 reputation: completed.
- https://example.com/ submission and saved-analysis retrieval: completed, 93 engine outcomes. Live URL analysis uses underscore names for some statistics; a failing regression led to canonical normalization of both supported spellings.
- Generated harmless text file, virustotal-smoke.txt: uploaded and completed, 75 engine outcomes. The initial accepted analysis temporarily returned HTTP 404, then became available. A regression now treats that as pending within the twenty-poll budget, without repeating the upload. Final report distinguishes 61 undetected and 14 unsupported outcomes.
- JSON export produced a browser download event. History search and type filter returned the correct single URL record. Refresh retrieved existing analysis IDs without resubmission.

No customer file or code was transmitted. The local development instance contains the four synthetic/benign external records and preserved its earlier account/PE scan. Secrets and the instance are excluded from source delivery.

Visually reviewed the desktop workspace and URL result, plus upload/history/file-result layouts at a 390-pixel viewport. Checked mobile menu expansion and no horizontal document overflow. The viewport override was reset. Browser checks establish the tested views, not complete accessibility or cross-browser certification. The final narrow-screen target layout was widened to keep full fingerprints readable.

Real schema migration to version 3 succeeded with a pre-upgrade backup. Doctor confirms schema 3, closed registration and recent backup; it still reports missing administrator MFA and both Docker processing images. The API workspace works independently of Docker. Local PE/document worker execution, offline Ghidra execution, automatic AI inference, workload evaluation and independent security acceptance remain pending. See REMAINING_FEATURES.md.

## VirusTotal connection check — 30 October 2026

After the local-hardening handover, the user supplied a VirusTotal API key. It was entered through the hidden configuration prompt, saved only in the ignored local .env, and restrictive Windows permissions were reapplied. The existing bounded provider adapter returned **available** for the SHA-256 of an empty byte string. This was one quota-accounted hash lookup; no file or code was uploaded. The key is not included in this document or source delivery. Local workers, administrator enrollment and AI inference remain separate prerequisites.

## Local server hardening — latest result, 30 October 2026

**66 passed in 62.81 seconds**, exit 0, from `.venv\Scripts\python -m pytest -q` after the independent-review fixes and Pillow upgrade. Python compilation, JavaScript syntax, PowerShell script parsing and pip dependency consistency checks passed. A provider subprocess startup check passed without credentials or network calls.

The isolated audit environment ran pip-audit 2.10.1 against requirements.lock.txt. It initially reported 39 advisories affecting Pillow 12.3.0. Pillow was upgraded to 13.0.0 and the audit rerun: **no known vulnerabilities found**, exit 0. Evidence: artifacts/dependency-audit.json on the development machine. This covers the pinned Python packages, not OS/container/Ghidra components or undiscovered vulnerabilities.

New coverage includes loopback/Host restrictions, closed registration, recovery-token hashing/expiry/single use, TOTP encryption/replay prevention, session expiry/revocation, concurrent limits, migration preservation, backup/restore locking/integrity, durable queue recovery/retries/deletion, provider streaming limits, worker timeout/output limits, fail-closed Docker configuration, and local/cloud findings provenance.

One independent read-only source review identified four Important findings. All were reproduced or covered by failing regressions before fixes: stale ORM security-version increments, invalid restores replacing live data, unbounded provider execution and backup failure starving provider jobs. Six new cases passed after fixes, followed by the full suite. Two additional readiness/UI regressions passed after removing false Ready labels and checking the requested local OpenBin image. No deferred Minor review findings remain.

The real instance migration preserved one existing account and one scan (before and after), upgraded to schema 2 and produced verified backup sentinel-20261030T053723Z-c4d1eea1.sqlite. Permissions were restricted on instance and .env. Existing old-format cookies were invalidated as intended. No real customer account or document key was changed.

Browser checks with CSRF enabled: existing synthetic preview sign-in, updated dashboard, settings, account-security forms and recovery form rendered. Desktop settings/security were visually checked. Settings and security had no horizontal document overflow at a 390-pixel viewport override (375 content pixels). The viewport override was reset. No production password or MFA enrollment was entered through automation. Earlier native-mode document/scan browser checks below remain historical; they are not Docker verification.

Live server: `/health` **200**, `/ready` **503**. Doctor exit 1 correctly reports database schema, closed registration and recent backup passing, with administrator MFA and both processing images pending. `tools/check_workers.py --include-openbin` exits 1 with the expected missing-Docker message. This is a real deployment blocker, not a passing runtime test.

Official OpenBin/BINNY binaries and source were downloaded and inspected. No sample/code was sent to their cloud. The official CLI's upload behavior motivated a separate offline Ghidra adapter. Actual Docker/Ghidra execution, live VirusTotal credentials, model inference, MySQL, load testing and independent penetration testing remain unverified. Windows build 22621 is below the current Docker Desktop Windows 11 minimum. See LOCAL_DEPLOYMENT.md for the acceptance procedure.

## Historical FYP verification (before local hardening)

Date: 30 October 2026. Platform: Windows, Python 3.12, local SQLite, Waitress. Dependency versions are recorded in requirements.lock.txt.

## Automated checks

Command: .venv\Scripts\python -m pytest -q

Result: **34 passed in 32.26 seconds**, exit code 0.

Coverage includes authentication, invalid identities, duplicate accounts, role restrictions, failed-login throttling, missing and valid CSRF tokens, disabled users, scan/report ownership, consent checks, administrator isolation, JSON hash/evidence binding, parser validation, provider failure states, encryption randomness, exact binary recovery, wrong keys, authenticated tampering rejection, malformed package lengths, capacity limits and quota timing.

Three independent-review regressions were observed failing before their fixes: oversized output PNG, a valid 2056-bit RSA key that could encrypt but not recover, and loss of epoch precision in the MySQL quota column. A browser-discovered valid-CSRF regression also failed before its configuration fix.

Python compilation: python -m compileall -q sentinel run.py tools passed. JavaScript syntax was checked using node --check sentinel/static/app.js.

## Browser checks

The local app was exercised in the Codex embedded browser with CSRF enabled:

- Created a local synthetic preview account and loaded the dashboard.
- Uploaded the generated inert PE fixture; observed SHA-256, x86 architecture, section data and truthful unavailable/manual source states.
- Downloaded the assessment PDF through a native browser download event; rendered and visually reviewed its page for layout and legibility.
- Checked the PNG image-capacity estimate.
- Submitted protection and observed a protected-PNG download event.
- Submitted recovery with a passphrase-protected private key and observed the recovered-document download event. Exact recovered bytes are independently asserted by integration tests.
- Generated an encrypted private-key/public-key ZIP and observed its download event.
- Searched scan history and verified the matching record.
- Visually reviewed the desktop dashboard at 1365 pixels and mobile dashboard/history at 390 pixels; verified mobile menu navigation and no horizontal document overflow after the fix.

JavaScript blob downloads did not produce reliable download events in the embedded browser. The delivered app uses standard form attachment responses, and protection, recovery and key generation were rechecked successfully with that implementation.

The preview account and its synthetic records exist only in the development instance. They are excluded from the source archive. Create your own account when using the project.

## Not verified externally

- Live VirusTotal service: no real provider key/request was used. HTTP behavior is tested with controlled responses.
- Real OpenBin/Ghidra/model execution: the delivered workflow validates a supervised JSON import. The app does not automate external decompilation or infer results.
- MySQL server or Docker runtime: configuration is supplied; these services were unavailable locally. MySQL column compilation was checked, while workflow tests used SQLite.
- Real malware datasets, detection accuracy, production load, public deployment, independent penetration testing and cross-browser certification.

The historical tests establish prototype behavior within the described scope. They do not certify safety of unknown binaries or production readiness. The latest local-hardening evidence is recorded at the top of this document.

## Interface refresh, 30 October 2026

Added a shared navy/emerald theme with stronger text contrast, larger controls, a new dashboard illustration, three primary workflow cards and actual recent account activity. Updated shared navigation and authentication styling; added a skip-to-content link and current-page navigation semantics.

Existing page-rendering, scan/history/report and valid-CSRF checks passed: 3 passed, 9 deselected in 6.54 seconds. No backend or cryptographic behavior was changed.

Visually checked the dashboard at 1440 and 390 pixels, analysis at 1440 and 390 pixels, document protection at 768 pixels, and login at desktop and 320 pixels. Checked document width at 320, 390, 768 and 1440 pixels without horizontal page overflow. Mobile navigation and sign-in succeeded. A narrow-screen heading spacing issue was corrected. Keyboard focus styling and skip navigation are implemented; the final automated keyboard check was interrupted by a browser-control timeout, so complete keyboard-accessibility certification is not claimed.
