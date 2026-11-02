# Key viewing and downloads implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this scoped follow-up.

**Goal:** Show each owner their assigned public and encrypted private PEM keys and verify the document and key downloads end to end.

**Architecture:** Keep the existing owner-scoped encrypted vault and native attachment responses. Add `action=view` to POST `/keys`, sharing current password/MFA verification and the isolated `export_keys` worker; display the re-encrypted export PEM in a no-store response. GET never renders private PEM. Existing POST clients default to `action=download`. No schema, crypto or worker-image change.

**Tech stack:** Flask, Jinja, native JavaScript, pytest, existing Docker document worker.

**Spec:** User's current request and existing `docs/superpowers/specs/2026-10-31-admin-account-keys-design.md`. The user has already requested implementation without further design questions.

## Constraints and review focus

- Every account may see only its own keys; posted user IDs never select another key.
- Private viewing retains fresh password, enrolled TOTP, CSRF, rate limits and trusted-server notice. Do not display the vault-encrypted value or its server-derived passphrase.
- Display the same key re-encrypted with the owner's chosen backup passphrase. No private PEM on GET, failed verification, browser storage, logs or admin pages.
- Consume MFA and release database writes before slow work. Audit viewing separately from downloading.
- Clear the displayed private key on Hide, page departure, or five-minute expiry; JavaScript disabled users retain a normal Hide link to GET `/keys`.
- Preserve native download behavior, which was reproduced successfully in the in-app browser before editing. Do not substitute blob downloads.

## Task 1 — Owner key viewer

Files: `sentinel/routes.py`, `sentinel/templates/keys.html`, `sentinel/static/app.js`, `sentinel/static/app.css`, `tests/test_key_view.py`.

- [x] Write tests for public visibility, no private PEM on GET, private view authentication/MFA, owner isolation, exact key-pair binding, view audit, malformed action, invalid passphrase and native download attachments.
- [x] Run tests before implementation; confirm failures identify the missing viewer.
- [x] Implement the action and responsive viewer with labeled readonly textareas, copy controls, private Hide/expiry, and explicit encrypted-PEM wording.
- [x] Run the new tests plus existing key workflows, crypto transaction and protection tests.

## Task 2 — Acceptance and handover

- [x] Restart only the verified local project server. Use existing preview credentials to verify public/private views, copy/hide, key backup and document download in the in-app browser.
- [x] Verify protected sample bytes recover exactly through the real local Docker worker.
- [x] Run the full suite using a fresh D: temporary directory (C: has low free space).
- [x] Review the small auth/UI diff, resolve material findings, update user guidance and verification, and refresh the source-only ZIP with privacy validation.

## Evidence

- Before editing: the in-app browser emitted a download event after clicking Protect & download with `examples/sample-document.txt`, `examples/cover.png` and assigned key. Capacity was 800 × 600. The form retained a processing notice after download, so wording will explain where to find the file without claiming detectable completion.
- Task 1 complete: five missing-view failures and five passing guard/download cases observed before implementation. After implementation, 32 focused tests passed in 166.75s. Evidence: artifacts/qa/key-view-red.txt and key-view-green.txt; exit files 1 and 0 respectively.
- Task 2 acceptance: live HTTP/Docker script exit 0; browser key view/copy/hide and all four key/document download controls verified. Details and browser-control limitations: artifacts/qa/key-view-acceptance.txt. Review found no Critical/Important issues.
- Ruling: continue in the existing uncommitted local project, which has no Git HEAD. Preserve the source ZIP baseline before packaging; no unrelated commits or worktree reconstruction. Cost: no commit-level change history for this task.

- Final regression: 164 passed in 362.00s (0:06:02), exit 0. Task 2 complete subject to the source-only package integrity/privacy check performed immediately after documentation refresh. Customer readiness limitations remain unchanged.
