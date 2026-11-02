# Professional workspace implementation plan

> For agentic workers: execute inline using superpowers:executing-plans, with a final independent review.

**Goal:** Apply the user's selected light professional design across every existing workspace.
**Architecture:** A single global stylesheet replaces the three overlapping themes. Templates retain routes, form attributes and client hooks; component styles use the same tokens.
**Tech stack:** Flask/Jinja, CSS, existing vanilla JavaScript.
**Spec:** ../specs/2026-11-02-professional-ui-design.md

## Constraints and review focus

- Preserve CSRF, action URLs, consent, key validation and download/progress hooks.
- Render real data only; distinguish configuration from actual runtime readiness.
- At 390px, forms fit the viewport and wide tables scroll internally.
- Keep primary/secondary/destructive actions and pending/error/completed status distinct.
- Keep focus visible and navigation functional for keyboard and touch.

## Tasks

- [x] Replace shared global styles and simplify shell, dashboard and login layouts.
- [x] Apply direct labels and consistent forms/tables to all task, history, key and admin screens; align component styles.
- [x] Run existing template/auth/admin/key/progress checks and client tests; add a focused regression only if interaction behaviour changes.
- [x] Inspect representative desktop and mobile pages in the real browser, including consent, navigation and preserved report links; cover error paths with existing tests.
- [x] Review the final changes, prepare the delivery archive and synchronize the reviewed source to the existing GitHub publishing checkout.

Validation: 117 Flask tests and 33 JavaScript tests passed. Browser checks covered desktop and 390px widths. Review fixes and verification scope are recorded in `docs/GUI_REFRESH.md`. Publication uses the user's existing authorization for the configured GitHub repository.

Ruling: no new tests that merely restate colours or CSS declarations. Existing functional tests plus visual inspection are appropriate for presentation-only changes; any interaction fix gets a targeted regression.
