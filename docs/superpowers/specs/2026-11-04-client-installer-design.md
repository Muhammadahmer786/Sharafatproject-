# Automated client setup

The user requests a Python program that performs the steps in CLIENT_SETUP.md and runs the application without manual dependency commands. This extends the approved Windows/local-only handover. Implementation choices below are the builder's defaults.

Use a standard-library Python entry point, with a double-click Windows bootstrap for Python 3.12. Reuse a working Docker engine or the configured dedicated WSL engine; otherwise install a dedicated Ubuntu/Docker engine. Support operator-owned C: storage as well as data drives. Keep existing WSL configuration. Do not install optional BINNY, Git, PowerShell 7 or MySQL when the running application does not need them.

Orchestrate existing worker/runtime installers, verified asset downloads, dependency installation, migrations, worker acceptance, local model download and a real inert-fixture AI acceptance. Store only stage fingerprints in ignored instance state. Recheck prerequisites on rerun. Never overwrite accounts, secrets, provider keys or an unrelated WSL distribution. Elevate only Windows feature installation, never silently reboot. Resume by launching the same entry point after reboot/failure. No scheduled tasks, public listener or hosting.

Ask privately for administrator credentials through the existing operator console. Prompt for an optional client VirusTotal key only when missing. Retain administrator MFA enrollment in the browser: installing an authenticator on a person's device cannot be automated safely. Start the site and open the browser after local acceptance; distinguish installed components from the remaining human MFA/provider acceptance.

Alternatives considered: a large self-contained executable complicates delivery and trusted updates; requiring Docker Desktop adds a separate UI/license flow. A thin Python orchestrator reuses existing verified components. An existing Desktop engine remains supported.

Testing must exercise real temporary state/configuration and the orchestration with OS/network subprocesses substituted. Do not reinstall WSL, download multi-GB assets, reboot, or modify the developer's live instance during verification. Fresh-client installation cannot be claimed from simulated tests.
