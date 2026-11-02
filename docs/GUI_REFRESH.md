# Professional workspace refresh

The interface now uses a light workspace, charcoal navigation and navy actions across sign-in, the dashboard, analysis, threat intelligence, documents, keys, history, settings and administration.

## What changed

- One shared `sentinel/static/workspace.css` replaces the three overlapping global themes. Fonts are provided by the operating system; no external font or image service is needed.
- The overview prioritizes real account totals, common tasks, recent records and tool configuration.
- Direct page titles, consistent forms, quieter panels and compact records replace decorative promotional layouts.
- Local AI reports, provider reports, progress bars and notifications use the same visual language and distinct status colours.
- Phone layouts stack forms and keep wide tables in their own scroll containers. Focus indicators and existing control labels are preserved.

This release changes presentation. It does not change backend routes, account permissions, encryption, API consent, model inference, upload limits or download handling.

## Verification — 2 November 2026

- 117 existing Flask tests passed across AI templates, workflows, authentication, key views, assigned-key operations, administration, intelligence, document progress, analysis updates and upload limits.
- 33 existing JavaScript tests passed for AI progress, completion notifications, polling, validation and document downloads.
- Browser inspection covered desktop and 390px phone layouts: sign-in, overview, local AI, OpenBin, file analysis, intelligence, reports, history, document protection/recovery, keys and settings. Administration used synthetic, read-only preview records, with real-account permissions unchanged.
- Mobile navigation, recipient-key switching and notification-to-report navigation were exercised. AI history/table overflow was reproduced and corrected by containing positioned screen-reader labels within the table scroll wrapper.
- An independent source review found recovery-code spacing, long account-name wrapping and six-stage progress alignment issues; all were corrected. No route, form, CSRF, consent, key or JavaScript-hook regression was found by that review.

No fresh external-provider submission or expensive model inference was needed for this visual update. These checks do not establish malware-detection accuracy or complete customer deployment acceptance.

## Updating an existing installation

Pull the latest source, restart the local application, then refresh the browser. Follow `GITHUB_HANDOVER.md` for the full update procedure and preserve the existing private `.env`, instance database and server secret.
