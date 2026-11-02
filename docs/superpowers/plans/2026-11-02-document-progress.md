# Document download progress implementation plan

> **For agentic workers:** Use superpowers:executing-plans for this scoped follow-up.

**Goal:** Replace the text-only document processing notice with an accessible animated progress bar for Protect and Recover, ending in a truthful download-started state.

**Architecture:** Preserve native multipart form submissions and attachment downloads. JavaScript generates a fresh 32-character hexadecimal request marker. Successful document attachment responses alone set a short-lived, non-secret completion cookie scoped to the route; the page observes and clears its matching cookie. No background document storage, new job API or guessed percentages.

**Tech stack:** Existing Flask/Jinja, vanilla JavaScript and CSS, pytest and Node's test runner.

**Spec:** User's request and screenshot in this task: show a progress bar when protecting/recovering and preparing the file download. Prior authorization to proceed without design questions persists. This short plan records the design for this small change.

## Constraints and choices

- Native download behavior was previously verified in the embedded browser; blob downloads were unreliable there. Retain native submissions instead of an XHR/blob rewrite. An asynchronous job store is unnecessary and would retain sensitive output.
- During upload/processing, show an indeterminate animation labeled Protecting/Recovering with no percentage. Only a matching server response marks preparation complete and says Download started; the page cannot observe completion of the browser's disk save.
- Completion cookies contain only `ready`, use a fresh random token in the name, expire after 120 seconds, are SameSite=Strict and inherit the secure-cookie setting. Route scoping and separate markers prevent cross-tab interference. They grant no access and contain no file/key data.
- Invalid/missing markers never change attachment behavior and never create cookies. Errors never emit a success marker; normal server errors navigate to their page. After five minutes without confirmation, stop the animation, restore the button and show a neutral status-unknown message. No automatic retry.
- Keep all form controls submitted, prevent duplicate submissions while waiting, preserve upload size validation and key/download notices elsewhere. Reduced-motion users receive a static busy indicator and accessible status text.
- Use the existing project and source ZIP baseline because this local repository has no Git HEAD. No unrelated git operations, dependencies or worker changes.

## Implementation and verification

- [x] Write and run failing Python regressions: success markers on actual protect/recover attachments, cookie attributes, invalid token handling, no success on errors, and form progress markup.
- [x] Add the server attachment marker and protection form markup. Add an isolated document-progress script, styling, and a small integration hook after size validation in app.js.
- [x] Test actual JavaScript with DOM/timer stubs: active state without fabricated percentage, duplicate prevention, matching cookie completion and clearing, stale/wrong cookie isolation, timeout recovery, repeated submissions and validation integration.
- [x] Run the appropriate Python document/auth/upload suites and Node checks. Restart only the verified local server, verify real HTTP/Docker attachment and exact recovery plus markers. Attempt browser verification; record tool limitations without implying a browser pass.
- [x] Obtain one fresh final review, resolve material findings, update user/verification guidance and refresh the source-only package; run integrity/privacy checks immediately after this documentation update.

## Ledger

- Pre-flight: app.js validates upload sizes before native submission. Document-progress begins only after validation passes and takes over the document notice; key/OpenBin forms keep their existing behavior. download() is shared, so marker emission must explicitly restrict itself to successful protect/recover attachments.
- Ruling: use no invented upload/crypto percentages. An animated bar satisfies the requested visible progress while preserving native download support.
- RED: Python regressions reported 3 expected failures and 7 passes in 27.91s. Five Node tests failed on the absent controller before implementation; a preceding sandbox process-spawn error was rerun with permission and is not counted as a regression failure.
- Client checks: 7 Node tests pass, plus JavaScript syntax checks and the existing upload-validation logic check. This uses DOM/timer stubs, not live browser automation.
- Independent final review found no material correctness or security issue. Native controls, marker scoping, duplicate prevention, cleanup and accessible/reduced-motion behavior were reviewed.
- Browser limitation: the in-app browser control tool again failed before accessing the page with a kernel-assets path error (os error 3). Browser rendering and cookie observation are not claimed as verified.
- GREEN: 63 Python tests passed in 163.12s (0:02:43), exit 0, covering document progress, upload limits, workflows, protection, assigned keys, key viewing and hardening. Evidence: artifacts/qa/document-progress-green.txt and document-progress-green-exit.txt.
- Live HTTP/Docker: check-live-document-progress.py exited 0. Both forms and assets served correctly; invalid requests emitted no marker; actual protected and recovered attachments each carried the correct route-scoped marker; recovered document bytes exactly matched the input. Evidence: artifacts/qa/document-progress-live.txt and document-progress-live-exit.txt.
- Source handoff includes the new .cjs tests. Keep the preceding source archive as Sentinel-Lab-Pre-Document-Progress-Source.zip; no account data, keys or environment files enter the allowlisted package.
