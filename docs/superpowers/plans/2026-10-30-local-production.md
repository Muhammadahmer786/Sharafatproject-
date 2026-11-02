# Local deployment hardening

User scope: keep Sentinel on this PC, use API keys for optional external services, download OpenBin's local tooling. No public hosting. Preserve the existing accounts and scan history.

## Design and acceptance

Use a single local application with SQLite, a durable metadata-only provider queue, administrator-controlled account creation, revocable sessions, password recovery through the local operator, optional TOTP for users and mandatory TOTP before administrator actions. Bind the web service to loopback and reject other Host/client addresses. Keep plaintext/key uploads in memory. Provide versioned database upgrades, verified backup/restore commands, readiness checks and an operations screen. API keys belong in a private local environment file. Retain honest integration states.

Use OpenBin's BINNY local decompilation workflow. Install official binaries in vendor without changing system PATH. Ghidra needs a local Docker engine; no sample/code may go to the OpenBin website automatically. Use local models or an explicitly configured provider key in BINNY. Any cloud processing still needs disclosure consent. Keep evidence review before import.

## Tasks (inline execution)

1. Add behavior tests for local access, account provisioning, session revocation, password reset and TOTP. Observe failures. Implement versioned schema migration and account security. Preserve legacy database data. Verify new and existing auth tests.
2. Replace the in-process reputation executor with durable database jobs, bounded retries, restart recovery and deletion-safe completion. Add failure/restart tests first. Keep global quotas and consent. Add per-user operation limits.
3. Implement atomic SQLite backup/restore with integrity validation, startup backup, local config loading, readiness/doctor commands, bounded logs and a supervised launcher. Test restore and migration with temporary databases before changing the user's database.
4. Download verified upstream OpenBin/BINNY tools, inspect their supported local interface, provide project-local launch instructions and actual prerequisite status. Add a hardened Docker PE worker option that fails closed when unavailable. Do not claim native Windows process separation is a malware sandbox.
5. Update settings/security/operations UI and local-vs-cloud evidence provenance. Exercise GUI and accessibility with the running local application. Preserve existing visual design.
6. Run the complete test suite, dependency audit and live smoke checks; obtain one fresh independent review per executing-plans. Fix material findings with regressions. Refresh documentation and source package. Report concrete remaining prerequisites rather than an unconditional production certification.

## Progress and rulings

- Setup: existing isolated sentinel-lab directory; parent repository has no HEAD. Changes stay here and no unrelated files are committed or removed. The user authorized implementation; optional provider preference was answered: API keys externally, OpenBin locally.
- Pre-flight: session schema is consumed by auth/CLI; job schema is consumed by worker/status/deletion; readiness uses the same config as execution. Test fixtures explicitly enable self-registration and native parsing, while deployment defaults remain restricted.
- Ruling: preserve this written ledger instead of deleting it; there is no Git commit history to recover it from. Cost: one additional documentation file.
- Ruling: OpenBin local tooling means BINNY/Ghidra on this PC, not the unrelated upstream multi-service social web platform. Cost: the upstream terminal is used for evidence review; Sentinel remains the main GUI.
- Task 1 complete: security regressions observed failing, then 13 auth/security cases passed. Migration preserves legacy users; session epoch revokes pre-restore cookies. TOTP codes are encrypted at rest and replay checked atomically.
- Task 2 complete: queue restart, lease, deletion and retry regressions observed failing then passed. A deterministic four-request race reproduced the old rate-limit defect; atomic database counters fixed it. Provider body limits and old reset-token invalidation also have RED→GREEN regressions.
- Task 3 complete at code/test level: online SQLite backup, offline restore lock, integrity validation, daily snapshots, CLI operations and readiness. A Windows open-handle failure was reproduced and fixed by explicitly closing SQLite connections before renaming backups.
- Task 4 prepared: official OpenBin v0.10.0 and BINNY v0.1.0-beta.3 binaries plus upstream source downloaded under vendor. CLI versions verified. Docker absent; actual Windows 11 build 22621 is below the current Docker Desktop minimum 22631. Container execution remains unverified and production upload processing fails closed.
- Ruling: the stock OpenBin CLI uploads decompiled code and BINNY requires login at startup. Use a local adapter around the official Ghidra worker instead, with network disabled and RAM-backed scratch space. Cost: an additional integration boundary requiring a real Docker smoke test before customer use.
- Task 5 implemented: account security, local server operations, integration readiness and local/cloud evidence provenance UI. Browser verification pending.
- Full regression suite before independent review: 58 passed in 51.38 seconds. No live provider request with a real key, Docker run or AI inference has been claimed.
- Task 6 in progress: independent review, dependency audit, actual local migration/backup, GUI verification and final packaging/documentation.
- Task 5 verified: live preview sign-in, settings/security/recovery rendering, desktop layout and narrow-screen overflow checks. Dashboard now reports unavailable workers honestly; regression observed failing before fix. No real account credentials or enrollment were changed.
- Final: fixed concurrent security-version reuse — stale-session password/revoke regressions RED→GREEN; all revocation paths use database expressions and preserved operation-issued session IDs.
- Final: fixed restore mutation before validation — malformed required-column and missing-table regressions RED→GREEN; stage and transform before atomic replacement.
- Final: fixed provider hard deadline — stalled child regression RED→GREEN; network execution moved to a separately bounded process with credentials on stdin and scrubbed environment.
- Final: fixed backup failure starving jobs — injected backup failure regression RED→GREEN; separate failure boundaries and five-minute backup retry.
- Final review fix suite: 66/66 passed in 62.81 seconds. No deferred Minor findings. Dependency audit initially flagged Pillow 12.3.0; upgraded to 13.0.0, then no known vulnerabilities. Pip consistency and Python/JS/PowerShell syntax passed.
- Final: Ruling: accept no certification of actual Docker/Ghidra/provider/model execution — those dependencies/credentials are unavailable here; fail closed and give concrete local acceptance commands — cost: customer use remains gated on those checks.
- Actual instance: one account/one scan preserved, schema 2, verified backup sentinel-20261030T053723Z-c4d1eea1.sqlite. Instance/.env permissions restricted. Health 200; readiness 503 correctly reports missing administrator MFA and both worker images.
- Task 6 verified within available host scope: tests, review, dependency audit, migration/backup and GUI checks complete; local runbook and source archive prepared. Live worker acceptance deliberately fails with missing Docker, matching the documented host limitation. Keep local files and the ledger; no Git integration exists in this unborn parent repository and no hosting was requested.
