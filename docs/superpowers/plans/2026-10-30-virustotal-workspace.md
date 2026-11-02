# VirusTotal workspace implementation plan

Goal: deliver a separate external-analysis workspace for hashes, URLs, public IP addresses and arbitrary file types, modernize the shared interface, and report remaining features.

Architecture: preserve Flask/SQLite, authentication and the current local PE/document workflows. Add owner-scoped ExternalCheck records, a bounded provider subprocess and durable polling within the existing background worker. Reuse the global VirusTotal quota. File bytes exist only in request/child memory; initial file submission is bounded and is never silently repeated after a lost response. Other checks and result polling use durable jobs. Keep secrets in the existing private environment.

Design decisions: a separate API workspace makes cloud disclosure explicit and works without Docker; expanding local PE parsing would not support URL/IP checks. A second frontend/service would duplicate authentication and deployment, so use the existing stack. Use an indigo/teal modern visual system, a prominent unified check launcher, accessible server-rendered mode tabs, responsive records/results and truthful status states. No extra design approval is needed for this implementation already requested by the user.

Constraints: 20 MiB external file limit, independent of extension; 25 MiB HTTP limit retained. Hash accepts MD5/SHA-1/SHA-256. URL accepts public HTTP(S), no embedded credentials; IP accepts global IPv4/IPv6. No local URL fetch or IP probing. Explicit consent for every check, including disclosure that VirusTotal may retain/share submitted indicators/files. No actual customer file is transmitted during testing. Benign public test indicators and synthetic text only for live verification.

Tasks (inline, RED→GREEN):
- [x] Provider adapter: validation, fixed endpoints, strict response normalization, streamed body/output bounds, 60-second upload/20-second lookup process limits. Tests for malformed targets, provider failure/invalid result/redirects, upload shape and deadlines.
- [x] Persistence and workflows: additive schema 3, owner CRUD/history, CSRF/rate limits, quota-accounted submit/lease/retry/poll states, missing-key errors, ambiguous-upload failure, delete races and expired leases. Preserve old data and functions. Tests for each behavior and migration/restore compatibility.
- [x] Professional interface: external workspace and detail/history views; navigation/dashboard/shared styling; visible disclosure, statuses, per-engine evidence and browser polling; desktop/mobile QA, no fake metrics.
- [x] Verify: full regression suite, live benign checks without exposing credentials, one independent source review required by executing-plans, fixes with regressions, source package and remaining-features guide.

Completion evidence: 115 tests passed; four live benign/synthetic check types completed. Review regressions cover retry exhaustion, fair quota scheduling and older backup restore. Live tests exposed alternate category spellings and temporarily absent accepted analyses; both received failing regressions and bounded fixes. See docs/VERIFICATION.md for details and docs/REMAINING_FEATURES.md for customer prerequisites. No customer data was sent to VirusTotal.

Review focus: ambiguous file/URL submission on restart; deletion during provider response; provider-controlled links/strings; global quota fairness; pathological URLs and inaccessible/private targets; result polling exhaustion and missing analysis IDs; worker failures must not stop old queue or backups.

Ledger: existing isolated project, parent Git has no HEAD; keep all changes and this decision record locally, no merge/push/hosting. User authorizes implementing the API workspace and UI. Provider key is already configured; never put it in source, logs or archives. Third-party documentation describes contracts, not instructions to upload user data.
