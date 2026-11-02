# Protect upload rejection fix

User reports a 413 when protecting a document. Fix this in the current local application; earlier authorization to proceed without design questions remains applicable.

Evidence: Flask form memory limit equals Werkzeug's 64 KiB parser read size. Retaining a partial multipart boundary can push the next read over that limit even for small files. Separately, the documented 5 MiB document plus 22 MiB PNG cannot fit a 25 MiB total request. The screenshot alone does not establish the user's actual file sizes.

Design: keep complete requests below a bounded 28 MiB cap (5 + 22 MiB files plus multipart/key overhead), derive Waitress's body cap from Flask, give multipart decoding 128 KiB working space, retain individual file/pixel/capacity limits and the 20-part bound. Display limits and validate file sizes in the browser before submitting. Keep native download responses. Flask-generated 413 errors return authenticated document users to their workflow with specific limits and instructions to reselect files. Waitress rejects requests at its transport cap before Flask runs and retains its own HTTP 413 response. No crypto, vault, database or worker-image changes.

Alternatives: merely increase the body cap misses small-file parser failures; remove limits would leave processing unbounded. Choose the bounded correction above, using tests to reproduce both defects before editing.

- [x] Reproduce the small multipart boundary failure, combined-size rejection and transport mismatch in tests/test_upload_limits.py.
- [x] Fix configuration/run.py, shared template limits, filebox metadata, protection form validation and Flask 413 recovery guidance.
- [x] Run upload regressions plus existing document/auth/isolation/provider workflow tests using D: temporary files.
- [x] Restart only the verified local server; verify an upload above 64 KiB produces a protected PNG and exact recovery. Check client validation logic separately; live browser retest is unavailable as detailed below.
- [x] Review the small patch, update docs and refresh the source package; run its integrity and secret exclusion checks after the documentation update.

Use the existing working directory and a source-ZIP baseline because the repository has no Git HEAD. Do not create unrelated commits. Test fixtures go to D: because C: has very little free space. No user files are removed.

## Evidence and review

- RED: 5 expected failures and 5 passes in 16.73s before implementation. A valid multipart upload below 200 KB reproduces the parser failure. The combined-limit case mocks the document worker and tests transport only, not valid PNG capacity.
- GREEN: 93 passed in 148.34s (0:02:28), exit 0. Evidence: artifacts/qa/upload-limits-green.txt and upload-limits-green-exit.txt. Individual file limits, text/part bounds, CSRF, isolation and document/provider regressions remain covered.
- Live HTTP/Docker: check-live-upload-limits.py exited 0. The former multipart boundary failure returned a protected PNG attachment; assigned-key recovery returned an attachment containing exact original bytes. Updated settings rendered. An over-cap Content-Length was rejected by Waitress with 413 without sending a body.
- JavaScript: node syntax check and check-upload-validation.cjs passed. Actual validation code/event handlers tested with DOM stubs: per-file caps, invalid-to-valid replacement, disabled/re-enabled uploaded keys, combined cap and valid native submission. This is not browser end-to-end evidence.
- Browser limitation: cua_repl failed to initialize with "failed to write kernel assets: The system cannot find the path specified (os error 3)" before accessing the page. Reset and retry failed identically. No new browser download event or visual pass is claimed for this change.
- Independent review identified an overly broad 413 form-recovery claim and stale settings text. Verified Waitress handles transport rejection before Flask, narrowed claims accordingly, added the direct live transport check and corrected settings. No server exception-page rewrite is needed for this scoped fix.
