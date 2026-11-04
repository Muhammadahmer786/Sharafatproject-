# Automated Client Setup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Client launches one entry point to install and run the local project.

**Architecture:** Python 3.12 standard-library bootstrap prepares the venv; the same interpreter then runs a resumable orchestrator around existing setup tools. Windows-only helpers perform narrowly scoped elevation and Python bootstrapping. Existing application authentication and runtime management remain authoritative.

**Tech Stack:** Python, pytest, Windows PowerShell, WSL/Docker, Ollama.

**Spec:** ../specs/2026-11-04-client-installer-design.md

## Global Constraints

- Windows x64, Python 3.12, loopback only; no automatic reboot.
- Preserve .env, database, original instance secret and existing WSL configuration.
- Do not persist passwords, API keys or subprocess output in setup checkpoints.
- Test using disposable state; no host installs or real provider submissions.

## Review Focus

- Interrupted setup/reboot: rerunning must verify prerequisites and resume without duplicate accounts.
- Existing engine/configuration: never replace a named distro or silently select another engine.
- C:-only computer/paths with spaces: explicit supported installation, correctly quoted subprocess arguments.
- Corrupt downloads/stale checkpoints: verify assets and actual installed prerequisites before reuse.
- Existing server/secret: stop before migration; never generate replacement vault secrets for a nonempty database.

### Task 1: Bootstrap and durable setup state

Files: setup_client.py, tools/client_setup_support.py, tests/test_client_setup.py.

- [x] Write failing tests for preserved config/state, interrupted stages, real fingerprint changes, path validation and read-only plan mode.
- [x] Implement standard-library state, subprocess and environment preparation; verify focused tests.

### Task 2: Installer orchestration and OS helpers

Files: tools/client_setup.py, tools/bootstrap-client.ps1, tools/enable-wsl.ps1, Setup-and-Run.cmd, tools/install-wsl-runtime.py, tools/install-local-ai.py.

- [x] Write failing tests for workflow ordering, rerun/failed stage, missing credentials, C: runtime support and owned WSL resume.
- [x] Implement actual probes and existing-tool invocation; add opt-in C: support and safe WSL resume to existing installers.
- [x] Validate PowerShell parsing and command help without installing anything.

### Task 3: Handover and verification

Files: README.md, docs/CLIENT_SETUP.md, docs/GITHUB_HANDOVER.md, tools/package_source.py, .gitattributes.

- [x] Document one-click/CLI startup, reboots, prompts and limits; include launchers in source ZIP.
- [x] Focused tests and read-only installer checks passed. Full-suite attempts were interrupted by tool-session disconnections; no full pass claimed.
- [x] Request one whole-change review while preparing delivery; resolve material findings.
- [ ] Package, audit exclusions, publish to the already-authorized GitHub repository and verify remote commit.

## Execution record

Implementation is inline in the existing source workspace; publication uses the separate clean D: checkout. No second application checkout is needed because new setup tools are not used by the running web process. Existing authorization covers implementation and GitHub publication; no new design approval is needed.

Final evidence: 27 installer tests, 16 related runtime/download tests and 33 JavaScript tests passed. Real CMD smoke test uses a harmless PowerShell stub; no real installation performed. Review fixes covered interrupted pip, complete dependency pins, per-distro config preservation and invalid-cache quarantine. Detailed limits are recorded in ../../VERIFICATION.md.
