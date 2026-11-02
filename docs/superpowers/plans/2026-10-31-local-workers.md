# Local OpenBin and document workers

User authorization: make the previously prepared OpenBin and steganography modules operational locally. Continue in the existing project directory; the parent repository has no committed baseline.

1. Install a dedicated Ubuntu 24.04 WSL 2 distribution on D:, using Microsoft's distribution manifest and SHA-256 verification. Keep downloads, virtual disk and swap off the nearly full C: drive. Install Docker Engine from Docker's official repository; expose no TCP daemon socket.
2. Add an explicit WSL Docker transport shared by PE, document and OpenBin workers and readiness checks. Preserve network denial, read-only containers, bounded pipes and cleanup. Never fall back to native processing.
3. Build the document/PE image and official OpenBin adapter, then run actual synthetic-file decompilation and exact-byte document protection/recovery checks.
4. Make local OpenBin decompilation accessible from the web interface, with bounded concurrency, input validation and truthful provenance. Keep AI/model inference explicitly separate from decompilation; only implement it if a genuinely local, supported setup can be installed and verified.
5. Run regression tests and browser verification, obtain one independent review, update operator instructions and remaining limitations. Do not claim production readiness without administrator MFA and remaining customer acceptance checks.

Constraints: no hosting, no automatic cloud decompilation or model calls, no Windows upgrade/reboot, no deletion of user files to free space. If an actual machine restriction prevents installation, report the concrete error and retain a reproducible setup path.

## Execution record

- Dedicated Ubuntu 24.04 WSL 2 and Docker Engine 29.9.2 installed on D:. No Windows upgrade/reboot. Docker info returned `linux`.
- WSL transport and web OpenBin tests: four failures reproduced before implementation; 19 focused tests then passed. Full suite: 119 passed in 102.74 seconds.
- Desktop/mobile OpenBin layout tested in headless Edge because the embedded browser tool failed to initialize. Screenshot verification found capture during a sidebar transition; the browser check now waits for the sidebar to finish hiding.
- The old OpenBin URL returned 404; the official release uses tag `openbin-v0.10.0`. The 663,034,322-byte archive is pinned to the publisher's SHA-256.
- A transfer ended at exactly 200 MiB and failed checksum verification. Added resumable 32 MiB ranges; interrupted-transfer and corrupt-cache tests failed before implementation and then both passed.
- First real PE container acceptance timed out. Diagnosis measured WSL cold boot at 14.16 seconds; Docker commands after boot took under one second and 5.4 GiB RAM was available. Added a separate bounded 30-second WSL startup margin, retaining parser/container limits.
- Automatic model inference is not implemented by this decompilation workflow. The UI and output provenance explicitly report that no AI model ran. This remains listed as additional product work, consistent with the existing supervised review/import scope.
- Actual isolated PE inspection and key generation/protect/recover acceptance passed after the WSL startup allowance.
- Final independent review found no Critical/Important issue in the inspected code. Two minor recovery issues were deferred: corrupt full-size cache files need manual quarantine; interrupted WSL installation needs operator recovery instead of rerunning the installer.
- Final: minor (deferred): automated recovery/reset for a corrupt complete OpenBin partial archive.
- Final: minor (deferred): resumable installation after a partial WSL import or Docker apt failure.
- Final: Ruling: actual Ghidra execution was deferred by the reviewer to runtime acceptance — the implementer must finish that check before claiming OpenBin works; without it the claim would be unsupported.
- Final: Ruling: independent hostile-file and upstream-image security audits remain outside this integration acceptance — customer security acceptance remains required; automated/synthetic checks do not establish resistance to every hostile file.
- Final: Ruling: unchanged authentication, provider and database code remains covered by the existing regression suite, not a repeated full code audit — independent customer security review remains required.
- Final: Ruling: documentation consistency is finalized against actual runtime evidence after the review — stale deployment claims must be corrected before handover.
- Settings regression: downloaded CLI presence did not reflect actual worker readiness. The new failing regression passed after switching the page to the shared image-availability check. Full application suite: 122 passed in 76.51 seconds.
- OpenBin archive completed and matched the publisher's SHA-256. First actual decompilation failed. An inert-fixture diagnostic identified Java's home directory `/nonexistent` for UID 65534; `HOME=/tmp` alone did not set Java's `user.home`. The adapter image now directs Java's home/temp to the RAM-backed `/tmp`, preserving the unprivileged read-only container. The inherited HTTP-service healthcheck is disabled for this one-shot worker. Runtime acceptance must be repeated before a success claim.
- Repeated complete worker acceptance after the adapter rebuild: exit 0. Static PE inspection, generated keys and exact document recovery all passed. Offline OpenBin produced one function with actual decompiled code and truthful no-AI provenance. Evidence: artifacts/qa/all-worker-acceptance.txt and all-worker-acceptance-exit.txt. The local server was restarted after an interrupted session and /health returned 200.
- Final complete browser acceptance passed, exit 0, including the actual OpenBin HTTP 200 JSON download, keys, PNG protection and exact-byte recovery. Desktop/mobile layouts were inspected and no page JavaScript errors occurred. Earlier harness deadlines were shorter than bounded server startup/processing; both action and navigation waits now accommodate them. Final doctor passes both images, database, registration policy and backup; administrator enrollment remains incomplete. Startup/load tests and disk capacity remain customer acceptance items. All five integration-plan implementation steps are complete within the stated supervised-review scope.
