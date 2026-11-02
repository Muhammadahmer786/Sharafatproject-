# Administration and Automatic Keys Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan inline, task by task. Steps use checkbox syntax for tracking.

**Goal:** Assign each account its own keys automatically and provide an MFA-protected user/activity management workspace.

**Architecture:** A dedicated account-key service wraps the existing isolated document worker and persists encrypted assigned keys. A single admin blueprint owns admin authorization and management routes. Existing user workflows consume the assigned key while preserving uploaded-key compatibility.

**Tech Stack:** Existing Flask, SQLAlchemy/SQLite, cryptography, TOTP, Waitress, Docker through WSL.

**Spec:** docs/superpowers/specs/2026-10-31-admin-account-keys-design.md

## Global Constraints

- Automatic assignment at account creation; idempotent assignment for legacy accounts after successful authentication.
- RSA-3072, encrypted PKCS8 private storage, per-account HKDF domain separation, export passphrase length 12–256.
- Owner-only private-key use/export with fresh authentication. All admin routes require administrator role and verified MFA.
- No new cloud services, dependencies, external messages, public hosting or default administrator credentials.
- Preserve existing files/accounts/old key recovery; metadata migration and staged restores support schema 2/3/4.
- Work in the existing dedicated project: the surrounding Git repository has no HEAD, so worktree/commit-based helper scripts cannot operate. Keep a file-based ledger and the existing source archive as the baseline; do not commit unrelated files.

## Review Focus

1. Concurrent first authentication must select one durable key and never silently rotate it (Task 1 race test).
2. Failed key generation must not leave an account without its assigned pair (Task 2 rollback test).
3. Copying a vault private PEM between accounts or changing the app secret must fail without replacing keys (Task 1 binding test).
4. New admin routes must not bypass MFA or expose another user's keys/content (Task 3 route matrix).
5. A schema-3 restore must preserve data and add new structures without modifying the source snapshot (Task 1 restore test).

### Task 1: Encrypted key service and migration

**Files:** models.py, database.py, operations.py, protection.py, document_worker.py, processing.py; new sentinel/account_keys.py; tests/test_account_keys.py and tests/test_operations.py.

**Interfaces:** AccountKey(user_id PK/FK, public_pem, private_pem, fingerprint, vault_version, created_at); audit(user_id, action, target_user_id=None). ensure_account_key(user) -> AccountKey does not commit caller work. vault_passphrase(user_id) -> str. export_keypair(private_pem, old_passphrase, new_passphrase, expected_public) -> (public_bytes, encrypted_private_bytes). Worker operation 'export_keys'.

- [x] Write/run failing behavioral tests: encrypted persistence/decryption, idempotence, cross-account binding, concurrency and safe export; schema-3 migration/restore preservation.
- [x] Implement the key service, worker export and schema 4/staged restore upgrades without weakening worker isolation.
- [x] Run `.venv/Scripts/python -m pytest -q tests/test_account_keys.py tests/test_operations.py tests/test_protection.py tests/test_isolation.py`; require all pass.

### Task 2: Automatic provisioning and user key workflows

**Files:** auth.py, routes.py, run.py, templates/keys.html, templates/protection.html; new tests/test_account_key_workflows.py; update relevant existing workflow tests.

**Interfaces:** Consume ensure_account_key and assigned-public/worker-export helpers. Registration/CLI account creation commits only after keys exist; password login and verified MFA assign only missing legacy keys. `/keys` exports the same assigned pair; `/keys/public` returns only the owner's public PEM. protect/recover choose `key_source=assigned|upload`; an uploaded file keeps legacy behavior when no source is specified.

- [x] Write/run failing tests for registration/CLI assignment, failed-generation rollback, legacy/MFA login, stable key exports, wrong-password denial, no cross-user access and assigned-key document recovery.
- [x] Implement provisioning and the owner key/protection forms with fresh authentication and existing rate/CSRF protections.
- [x] Run `.venv/Scripts/python -m pytest -q tests/test_account_key_workflows.py tests/test_auth.py tests/test_workflows.py tests/test_hardening.py`; require all pass.

### Task 3: Admin accounts and activity workspace

**Files:** new sentinel/admin.py; __init__.py, routes.py, security.py, templates/base.html; admin dashboard/users/detail/activity/code templates and existing CSS; new tests/test_admin_workspace.py.

**Interfaces:** Blueprint admin under `/admin`, central role/MFA guard. Dashboard `/admin`, users `/admin/users`, create POST `/admin/users/create`, detail `/admin/users/<id>`, actions `toggle`, `revoke-sessions`, `recovery-code`, activity `/admin/activity`, operations `/admin/operations`. issue_reset_token(user, actor_id=None) records actor/target when supplied. Ordinary-user actions only; admin accounts are read-only here.

- [x] Write/run failing route-authorization matrix and admin create/activation, disable/revocation, actor/target audit, filtering/pagination and private-content-exclusion tests.
- [x] Implement the guarded backend and responsive pages. New users receive assigned keys plus a one-time account setup code; display no key/private content to admins.
- [x] Run `.venv/Scripts/python -m pytest -q tests/test_admin_workspace.py tests/test_hardening.py tests/test_account_key_workflows.py`; require all pass.

### Task 4: Integration, review and handover

**Files:** Dockerfile if required by worker code placement; tools/check_workers.py; README.md and docs guides/verification/remaining work; artifacts/qa browser fixtures and logs.

- [x] Run the full `.venv/Scripts/python -m pytest -q` and record its exit code/output.
- [x] Rebuild only the file/document image from cached dependencies and run real export/protect/recover checks.
- [x] Stop only the verified project server, migrate with pre-upgrade backup, restart hidden and verify health. Confirm preserved row counts and assigned-key provisioning for the existing preview user at authenticated login.
- [x] Run isolated browser acceptance for real admin MFA, account creation/code redemption, key assignment/export, assigned-key recovery and desktop/mobile admin/key layouts.
- [x] Obtain one fresh final code review under executing-plans, fix material findings with failing regressions and rerun the full suite if changed.
- [x] Update custody/backup/user/admin documentation, verification and remaining limitations. Rebuild the source-only ZIP and verify private configuration exclusion. Report real administrator enrollment as operator setup, not a completed action.

## Execution ledger

- Ruling: The user's repeated instruction is an opt-out from further design questions. Proceed with automatic server-managed encrypted assignment as stated in commentary; no claim that they chose specific cryptography.
- Ruling: No committed Git baseline exists. Use this ledger and the existing source ZIP; no worktree/branch or unrelated-file commits.
- Pre-flight: Task 1 supplies the account-key model/service and worker export consumed by Task 2; Task 2 supplies automatic provisioning used by Task 3. Task 3 and existing authentication share issue_reset_token with an optional actor argument. Restore must accept both new table/column changes together. No interface conflict.
- Task 1: complete — seven missing-feature failures observed, then 29 key/migration/protection/isolation tests passed in 31.96 seconds. SQLite legacy test fixtures rebuild the audit table because DROP COLUMN cannot remove an inline FK constraint. Evidence: artifacts/qa/account-keys-red.txt, account-keys-green.txt and account-keys-green-exit.txt.
- Task 2: complete — nine missing-feature failures observed, then 30 workflow/authentication/hardening tests passed in 99.43 seconds. Owner forms now expose assigned-key export and protect/recover defaults. Evidence: account-key-workflows-red.txt, account-key-workflows-green.txt. Template integration also covered by the Task 3 run.
- Task 3: complete — eleven missing-feature failures observed, then 29 admin/hardening/assigned-key tests passed in 105.45 seconds. All admin routes use one role/MFA guard. Evidence: admin-workspace-red.txt, admin-workspace-green.txt and exit file (0).
- Task 4: in progress — cached document worker rebuilt successfully with export_keys; current-schema encrypted-vault backup preservation check added to integration coverage. Fresh review uses file comparison with the pre-change source ZIP because no Git HEAD exists.

Final: Ruling: Administrator recovery codes can allow takeover of a non-MFA account — retain this explicit account-recovery capability, treating administrators as trusted identity verifiers; no direct impersonation button or cross-owner content/key endpoint is supplied. Document that account recovery is an administrator trust boundary. Cost if wrong: a malicious administrator can reset a non-MFA owner password and access that account. Owners can enroll MFA; recovery codes do not remove it.
Final: Ruling: MySQL is optional and remains outside this verified SQLite deployment. Cost if assumed supported without validation: migration/concurrency behavior may differ.
Final: Ruling: Real Docker/browser/migration and suite outcomes are verified by the implementer separately, not inferred from review. Cost of skipping them would be unsupported deployment claims.
Final: Ruling: Original server-secret custody remains with the trusted machine operator. Cost if the secret is lost: the assigned vault cannot be unlocked; owner exports provide an independent backup.
Final review: no Critical or Minor findings. One Important finding reproduced in four route-level tests: independent SQLite writes failed during login key generation, legacy assigned-key protection, MFA export and MFA recovery (database is locked).

Final: fixed SQLite write locks during slow key workers — test_crypto_routes_release_writer_before_worker (four route cases) RED→GREEN; full suite 154/154.
Task 4: complete — 154 passed in 262.13s (0:04:22); Docker export/recovery and live assigned-key checks exit 0; browser admin/MFA/owner roundtrip exit 0; schema4 migration and new verified backup preserved local records. Readiness requires real administrator MFA setup. Source archive privacy verification is the final packaging check.
Final: Ruling: The uncommitted local project has no integration branch or Git HEAD, so finishing-a-development-branch retains the working files and source ZIP; no merge, push or cleanup menu applies. Cost if wrong: Git history must be initialized separately before collaboration through commits.
Final: Ruling: C: exhausted space during testing; rerun all tests using a new disposable D: directory instead of deleting user files. Cost if unresolved: the live application can also fail database writes when C: is full.
