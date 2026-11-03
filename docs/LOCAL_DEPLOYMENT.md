# Local deployment and operator runbook

**Installing on a new client PC?** Use the [step-by-step client setup guide](CLIENT_SETUP.md) for requirements, cloning/ZIP downloads, both Docker routes, model installation, first login and acceptance checks. This runbook contains additional operator procedures and historical details about the developer's workstation.

Scope: one operator-managed workstation/server, browser access on that same machine, SQLite metadata and no hosting or LAN exposure. The separate external hash/URL/IP/file workspace requires a VirusTotal key and disclosure consent. Local OpenBin decompilation uses an offline container; the [Local AI workspace](LOCAL_AI.md) adds local model inference and saved evidence-linked reports.

## Current handover status — 2 November 2026

The local AI upgrade adds schema 5 and the `ai_analysis` table. A protected pre-upgrade schema-4 backup was verified, and all existing records were preserved: one user, two scans, seven external checks and one assigned account key. Local Ollama/Qwen3 setup and runtime start commands are documented in [LOCAL_AI.md](LOCAL_AI.md). Ordinary `start.ps1` starts the installed AI runtime without downloading models. No Windows service or public hosting was installed.

The application starts on 127.0.0.1:5050. Existing records survived the additive migration to schema 4, which adds encrypted assigned account keys and targeted activity events; a pre-upgrade backup was created. Counts at migration were one account, one scan, five external checks and 32 activity events. Existing accounts receive keys at their next successful sign-in. Local state and .env permissions are restricted to the Windows operator, SYSTEM and administrators. The existing instance remains a development preview and is excluded from the delivery ZIP.

This PC runs **Windows 11 Pro build 22621.4317**. A dedicated **SentinelLab** Ubuntu 24.04 WSL 2 distribution and Docker Engine are now installed in **D:\SentinelRuntime**. This uses Docker Engine's supported Ubuntu route, without Docker Desktop or a Windows upgrade. The application selects this engine with `SENTINEL_WSL_DISTRO=SentinelLab`. The new `.wslconfig` caps WSL at 6 GB RAM and two processors and disables swap, avoiding the nearly full C: drive. These limits are global to WSL; review them before adding unrelated distributions.

OpenBin v0.10.0 and BINNY v0.1.0-beta.3 binaries and source are downloaded under vendor. Worker execution evidence is recorded in VERIFICATION.md. VirusTotal is configured privately and excluded from the source ZIP. Local AI runtime setup is documented in LOCAL_AI.md. Real administrator enrollment and representative AI evaluation remain acceptance items.

## Clean installation

Use Python 3.12 and a supported Docker Linux-container runtime. Extract source to an operator-owned folder on a local disk, not a shared/cloud-synced directory. Run PowerShell there:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python -m pip install -r requirements.lock.txt
Copy-Item -LiteralPath .env.example -Destination .env
.venv\Scripts\python run.py migrate
pwsh -NoProfile -File .\tools\secure-local-files.ps1
```

Copy .env.example only on a **new** installation. Never overwrite existing .env, instance/.secret or database files. A blank SECRET_KEY preserves the generated instance/.secret. If supplying a key, use a persistent random value of at least 32 characters. Changing it invalidates sessions and prevents decrypting existing authenticator enrollments and assigned private-key vaults. Never rotate or replace it without an explicit vault migration procedure.

Keep ALLOW_REGISTRATION=0, PE_WORKER_MODE=docker and COOKIE_SECURE=0 for the supplied loopback HTTP configuration. Unknown Host headers and non-loopback clients are rejected. Do not disable protections to share this deployment through a proxy or tunnel.

## Workers and local OpenBin

Use a directly installed Docker Linux-container engine, or install a dedicated WSL runtime on a data drive with at least 12 GiB free. The installer refuses to overwrite an existing distribution or `.wslconfig`, downloads Ubuntu from Microsoft's official manifest and verifies its SHA-256. It installs Docker Engine from Docker's official apt repository and never reboots Windows:

```powershell
.venv\Scripts\python tools/install-wsl-runtime.py --directory D:\SentinelRuntime --distro SentinelLab
```

Set `SENTINEL_WSL_DISTRO=SentinelLab` in private `.env` for this route; leave it blank for a direct Docker CLI. Docker starts through systemd in the dedicated distribution. Confirm or start it after an operator shutdown with `wsl -d SentinelLab -u root --exec systemctl start docker`. No TCP Docker socket is exposed. The Windows account that runs the web server must own the WSL distribution and is trusted with its Docker engine.

Build the workers:

```powershell
pwsh -NoProfile -File .\tools\setup-workers.ps1 -IncludeOpenBin -CacheDirectory D:\SentinelRuntime\downloads
```

This builds the pinned Python file/document worker, downloads the official Ghidra image archive and builds the offline adapter. It does not execute samples or log into OpenBin. Build-time downloads require internet; processing containers disable networking. The Ghidra archive SHA-256 is pinned. The correct OpenBin release tag is `openbin-v0.10.0`; the former `v0.10.0` URL returned 404. See THIRD_PARTY.md. Keep the cache and WSL virtual disk on a drive with sufficient free space. The separate `tools/install-openbin.ps1` script downloads optional upstream OpenBin/BINNY CLI tools; it is not required for the web workers or local AI pipeline.

**Do not replace the local adapter with openbin decompile:** the inspected upstream CLI uploads decompiled code. BINNY's inspected startup also requires upstream authentication. Use:

```powershell
.venv\Scripts\python tools/openbin_local.py examples/synthetic-demo.exe --output artifacts/local-decompilation.json
```

The output path must be new. Alternatively, sign in and open **Local OpenBin** in the sidebar, upload an authorized EXE/DLL and download its analysis JSON. One web decompilation runs at a time; allow up to six minutes including startup. The container has a read-only root, no host mounts, no network, reduced privileges and resource/time limits. Sample/project/result scratch files exist in tmpfs. The chosen local JSON is deliberately saved and may contain sensitive code. The web app retains only a completion audit event for this operation, not the input binary or extracted code. A cold WSL VM can take around 15 seconds to start on this PC; transport deadlines include a bounded 30-second startup margin.

Raw decompilation does not itself run AI. Use the separate **Local AI** page for automatic local Ollama review after extraction. It requires installed local weights and has no cloud fallback. The existing manual reviewed-findings import remains available with explicit provenance.

## Accounts and startup

```powershell
.venv\Scripts\python run.py create-admin
.venv\Scripts\python run.py create-user
.\start.ps1
```

Passwords are prompted privately; never pass them on command lines. Use a unique administrator account. Sign in and open Workspace settings → Account security to enroll a standard TOTP authenticator. Admin controls are blocked until enrollment and verified sign-in. Email addresses are identifiers; the app sends no verification/recovery email. Every newly created account receives assigned keys before it is saved. Once MFA is enrolled, Admin workspace → Accounts creates ordinary users and displays a single-use 30-minute setup code; the user chooses a password through Recover your account. Account details and Activity provide access controls, session revocation and searchable actor/affected-account records.

Passwords require 12–128 characters. Security changes revoke sessions atomically. Sessions expire after 30 idle minutes or eight hours from sign-in. A TOTP code is single-use; wait for the next code after using one. Keep the local clock accurate.

The optional `.\start.ps1 -Supervise` restarts on failure up to five times. It is a foreground operator process, not an installed Windows service; sign-out/reboot stops it. Arrange an operator-owned startup procedure if continuous availability is needed. Ctrl+C stops the server. Do not run multiple instances against one database.

## Optional VirusTotal API key

```powershell
.venv\Scripts\python tools/configure-virustotal.py
.\tools\secure-local-files.ps1
```

Enter the key in the hidden terminal prompt, then restart. Do not paste it into chat/screenshots. The helper writes private .env. Use a key licensed for the customer's intended use; consult [VirusTotal API terms](https://docs.virustotal.com/reference/public-vs-premium-api).

Local PE assessments send only their consented SHA-256. In the separate Threat intelligence workspace, hash/IP checks send the indicator, URL checks submit the complete URL, and File upload sends all file bytes. VirusTotal may retain/share these submissions. File bytes are held in bounded memory and never stored in the local database; submitted targets and result metadata are retained.

All modes share one request per 16 seconds and at most 500 per UTC day. Jobs stop after three consecutive failed/interrupted attempts or twenty analysis polls; a valid pending response resets the failure budget. Budgets are persisted before transmission. The scheduler rotates queue priority after quota consumption. URL/file submission with an uncertain outcome is never silently repeated. A process deadline bounds file upload to 60 seconds and other calls to 20 seconds. File submission runs during the request with two concurrent slots; accepted analysis IDs are polled in the background. Other checks use durable jobs. Unknown reports, unsupported formats, access errors and quotas remain explicit.

## Backups and restore

```powershell
.venv\Scripts\python run.py backup
```

Verified snapshots go to instance/backups. Startup creates one if needed; the background worker checks hourly for a daily snapshot. Scheduled failures back off without stopping provider jobs. Monitor disk space and rotate backups yourself; no automatic deletion occurs. Keep a protected copy on another local disk for disk-failure recovery.

Securely back up instance/.secret (or the configured SECRET_KEY) separately; it decrypts TOTP enrollments and derives the assigned key-vault passwords. Schema-4 database backups include encrypted assigned private keys and public keys. Both database and original secret are required for recovery. Owners should also keep an exported encrypted key backup and its separate passphrase. Agree retention with the customer: scan deletion does not erase old snapshots. Copies outside instance need their own permissions and disk encryption. SQLite encryption and physical secure deletion are not claimed.

Stop the server and database tools before restoring a schema-2, schema-3, schema-4 or schema-5 backup:

```powershell
.venv\Scripts\python run.py restore --backup "D:\LocalBackups\sentinel-backup.sqlite" --confirm-restore
.venv\Scripts\python run.py doctor
.\start.ps1
```

Replace the example path with a real backup. Restore validates and transforms a temporary database before replacing live data, checks required tables/columns and references, saves a snapshot of current data and revokes sessions/recovery tokens. Schema-2/3 snapshots are upgraded only in the staged copy; the backup remains untouched. It refuses a running server or incompatible input. Test on a separate copy before relying on recovery. Machine-to-machine restores also need the original secret. Backups older than schema 2 must first be migrated in a separate instance.

## Recovery

After local identity verification:

```powershell
.venv\Scripts\python run.py reset-password --email person@example.test
```

Give the one-time code directly to the owner; it expires after 30 minutes and is stored only as a hash. They use /reset-password to choose a new password. Do not save the code in logs. This does not remove MFA or rotate assigned keys; the existing vault remains available after password recovery. It cannot reconstruct a missing external key or lost server secret.

For a lost authenticator, run `run.py reset-mfa --email person@example.test`. It requires typing RESET MFA after identity verification, revokes sessions and removes enrollment. The owner must enroll again. OS operator access is therefore security-sensitive.

## Acceptance before customer use

1. Run `.venv\Scripts\python -m pytest -q` and audit the installed dependency lock against current advisories.
2. Build both images and run `.venv\Scripts\python tools/check_workers.py --include-openbin`. Preserve the result; image presence alone is insufficient. It uses synthetic inputs and temporary in-memory keys/documents.
3. Create real accounts, enroll admin MFA and verify separation/recovery using disposable test accounts.
4. In the browser, inspect the inert PE, download its PDF, verify automatic key assignment/export, protect/recover the sample document and compare SHA-256. Confirm wrong-key and modified-image rejection. Repeat with actual Docker processing; prior native-mode tests do not establish container compatibility.
5. Run local OpenBin and the Local AI pipeline. Review code quotations, model digest, omissions and failure states; use tools/evaluate_local_ai.py with independently labeled exports for a representative benchmark.
6. Test hash/IP lookup and URL/file submission with the permitted API key, disclosure consent and benign synthetic inputs. Confirm quota/error behavior. Use a customer-appropriate VirusTotal license; the public API is not a commercial-service entitlement.
7. Test backup/restore on a disposable copy, confirm session revocation and document recovery ownership/retention. Doctor and /ready should pass after prerequisites; /health should return 200.
8. Agree workload and test capacity on the actual workstation. Independent penetration testing, support arrangements, hostile-file corpus evaluation and complete cross-browser/accessibility certification are not established by the current automated tests.

## Optional MySQL

SQLite is the validated path. compose.yaml contains only a MySQL 8.4 database on 127.0.0.1:3306, not a web service. Supply distinct MYSQL_PASSWORD/MYSQL_ROOT_PASSWORD and run `docker compose up -d db`. Configure DATABASE_URL for the dedicated account. Use database-native backups and validate migration separately; the SQLite readiness backup check is not a MySQL backup monitor. Do not switch a customer database without a tested migration.

## Troubleshooting

- Setup required: ensure Docker Linux containers are running and both images are built. Processing fails closed.
- Doctor exit 1 or /ready 503: inspect checks; expected on this PC until prerequisites are complete.
- File permission denied: run as the Windows operator who secured the folder; preserve the restrictive ACL.
- Startup backup failure: check disk space/access. Startup refuses to proceed without its required backup.
- Pending provider: check key, quota, connectivity and job counts. File submission can occupy its request for up to 60 seconds; other checks and result polling run in the background.
- Logs: bounded warning/error events are in instance/logs. Sensitive exception content is omitted; detailed diagnosis should use synthetic inputs in a separate development instance.

Account recovery is privileged: a recovery administrator can reset a non-MFA account password and then access it. Grant the administrator role only to trusted identity verifiers. Owner MFA remains required after recovery. The local operator separately controls MFA reset and the vault secret. Database backups now contain encrypted assigned keys; preserve the original secret and test restoration with a disposable key before relying on backup.
