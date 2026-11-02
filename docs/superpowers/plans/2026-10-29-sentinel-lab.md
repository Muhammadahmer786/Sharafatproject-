# Sentinel Lab Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** Build the university FYP web application with real document protection, private scans and reports, safe static PE inspection, and supervised OpenBin findings.

**Architecture:** Flask app factory, SQLAlchemy persistence, authenticated server-rendered pages with progressive JavaScript. PE parsing runs in a bounded child process without executing the file; optional VirusTotal hash lookups run in a separate worker. OpenBin is a supervised external workflow with validated, hash-bound findings import, never fabricated AI.

**Tech Stack:** Python 3.12+, Flask, Flask-SQLAlchemy, Flask-Login, Flask-WTF, MySQL/PyMySQL, SQLite local fallback, cryptography, Pillow, pefile, ReportLab, Waitress, pytest.

**Spec:** ../../FYP_Requirements_Analysis.pdf plus the original seven-page client proposal; user authorized implementation on 29 October 2026.

## Global Constraints
- No execution of uploaded binaries or documents. Only PE x86/x64 native EXE/DLL files, 10 MiB maximum.
- No cloud transfer by default. Hash lookup and cloud OpenBin consent are explicit and separate.
- AES-256-GCM, RSA-OAEP SHA-256, fresh keys/nonces, lossless RGB PNG LSB embedding; 12 million pixels, 5 MiB document limit, 25 MiB whole request limit.
- Trusted local server handles keys/plaintext in memory only; no claim of end-to-end encryption.
- User-owned records, global CSRF protection, hashed passwords, no public registration elevation, no hardcoded credentials.
- Sample bytes are not persisted. Parser input is stdin; worker resource timeout is bounded. Deployment is local by default.
- MySQL configuration ships; immediate demo runs SQLite because no MySQL server is installed.
- Unconfigured reputation and unimported AI findings remain visibly unavailable/awaiting review.

## Review Focus
- Malformed PNG/package length and excessive image dimensions must fail before allocation/decryption.
- Another user and the admin role must not acquire scan/report content through guessed IDs.
- Tampered keys/ciphertext/metadata must produce no plaintext download.
- External timeouts, malformed provider data and unconfigured keys must not create a safe verdict.
- Imported findings must be bound to scan SHA-256, consent, evidence and reviewer provenance.

### Task 1: authenticated application and persistence
Files: sentinel/__init__.py, models.py, auth.py, templates/auth.html; tests/test_auth.py.
Interfaces: create_app(config=None), db, User, Scan, AuditEvent, login_required routes.
- [x] Write integration tests for register/login, invalid input, duplicate identity, CSRF and account disable.
- [x] Run tests and verify missing implementation fails.
- [x] Implement factory, DB models, hashed accounts, request protections and auth.
- [x] Verify tests pass.

### Task 2: authenticated encrypted PNG package
Files: sentinel/protection.py, tests/test_protection.py.
Interfaces: protect_document(document, filename, png_bytes, public_pem)->bytes; recover_document(png_bytes, private_pem, password=None)->(filename, bytes); generate_keypair(passphrase)->(public, private); image_capacity(png_bytes)->dict.
- [x] Test exact binary roundtrip, wrong RSA key, damaged ciphertext/header, insufficient capacity, large pixels, ordinary PNG, bad key and paths.
- [x] Observe failures, implement bounded versioned package and crypto, then verify full suite.

### Task 3: PE assessment, reputation, supervised evidence and PDF
Files: sentinel/analysis.py, pe_worker.py, reputation.py, reports.py; tests/test_analysis.py.
Interfaces: inspect_pe(bytes, filename)->dict; lookup_hash(hash,key)->dict; validate_findings(payload, sha256)->dict; render_report(scan)->bytes.
- [x] Test valid synthetic PE, invalid/oversized/.NET variants, import hash mismatch and unsafe evidence, provider failures and PDF consistency.
- [x] Implement bounded local parser, metadata/indicator findings, honest provider statuses, supervised findings schema, PDF.
- [x] Run full suite.

### Task 4: full product interface and workflows
Files: sentinel/routes.py, templates/*.html, static/app.css, static/app.js; tests/test_workflows.py.
Interfaces: dashboard, analyze, scan detail, history, protect, recover, key generation, settings/help, admin accounts; POST import/delete and report download.
- [x] Test upload/result/history/report, ownership, review consent, protection/recovery HTTP flows, sanitized activity records and admin restrictions.
- [x] Implement responsive navy/teal product UI and accessible forms, drag/drop, capacity display, inline progress, search/filter, pagination.
- [x] Verify suite and browser flows desktop/mobile; fix observed issues.

### Task 5: package, documentation, review and handoff
Files: README.md, docs/USER_GUIDE.md, docs/EVALUATION.md, examples/*, requirements.txt, Dockerfile, compose.yaml, run.py, start.ps1, tools/make_demo_files.py, tools/package_source.py.
- [x] Document installation, local/MySQL modes, supervised OpenBin protocol, consent, security limits, retention and academic evaluation.
- [x] Supply benign fixtures and example findings with obvious demonstration labels; no fake default scan results.
- [x] Run full tests, compile checks, browser QA and independent security/code review.
- [x] Fix material findings with regression tests; create source ZIP without credentials/runtime data.
- [x] Start local app, open it, and report working features plus unverified integrations.

## Execution decisions
User's request to build now authorizes routine implementation choices and inline execution. No further design gate is introduced. A new subdirectory isolates the project from unrelated planner artifacts; the surrounding Git repository has no initial commit, so a HEAD-based worktree is unavailable. Work is retained locally; no push or deployment.
