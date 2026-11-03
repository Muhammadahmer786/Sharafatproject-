# Sentinel Lab — local server edition

A local workspace for VirusTotal hash, URL, IP and file checks, static Windows PE assessment, local OpenBin/Ghidra AI triage, reviewed evidence, and encrypted document protection in lossless PNG images. Originally built for a university FYP, now hardened for an operator-managed local deployment. No public hosting is configured.

**Installing on the client's PC? Start with the [complete step-by-step client setup guide](docs/CLIENT_SETUP.md).** It covers system requirements, Git clone or ZIP download, Python, Docker, OpenBin, local AI/model downloads, API configuration, first login, verification, daily startup, backups and updates. It includes both a data-drive setup and a C:-only alternative. Plan for Windows 11 x64, 16 GB RAM (32 GB recommended) and about 40 GB free SSD space for the full setup; see the guide for qualifications and current vendor requirements.

**Handover status:** accounts/admin activity, encrypted account keys, separate VirusTotal checks, document protection, local OpenBin and automatic local AI triage are implemented. WSL 2 / Docker and Ollama/Qwen3 assets are installed on this PC's D: drive. Real OpenBin → local model → saved report → notification/download acceptance passed with an inert executable; see [verification](docs/VERIFICATION.md). Customer acceptance still requires administrator enrollment, workload/security validation and representative AI evaluation. See [remaining work](docs/REMAINING_FEATURES.md) and [local deployment](docs/LOCAL_DEPLOYMENT.md).

## Get the project from GitHub

Clone the project and enter its folder:

```powershell
git clone https://github.com/Muhammadahmer786/Sharafatproject-.git sentinel-lab
cd sentinel-lab
```

For a private repository, the repository owner must give the client access first. Follow the [client setup guide](docs/CLIENT_SETUP.md) for first installation and [GitHub handover and updates](docs/GITHUB_HANDOVER.md) for subsequent `git pull` updates.

The repository contains source and setup scripts. Each computer needs its own Python environment, local Docker/OpenBin workers, AI model, accounts and private configuration. Git does not transfer the developer's API key, accounts, encryption keys or installed runtimes. Initial setup downloads require internet; a clone alone does not install these components.

## Start on this PC

The existing virtual environment and metadata instance are preserved. From this folder:

```powershell
.venv\Scripts\python run.py
```

Open [Sentinel Lab](http://127.0.0.1:5050/). Accounts are issued by the local operator; registration is closed by default. No default credentials are shipped. Processing requires the isolated Docker worker and shows a setup error when unavailable. Native mode is a deliberate demonstration-only option, never a silent fallback.

The server starts and monitors the installed local model runtime automatically. Keep its terminal open. For server retry supervision with PowerShell 7, use `pwsh -NoProfile -File .\start.ps1 -Supervise`. No Windows service or automatic startup task is installed.

Follow [LOCAL_DEPLOYMENT.md](docs/LOCAL_DEPLOYMENT.md) for clean installation, accounts, worker setup and recovery. Windows / Python 3.12 / SQLite / Waitress is the verified application configuration. MySQL is optional and unverified.

## Included

- MFA-protected admin workspace: account creation, enable/disable, session revocation, one-time recovery codes and searchable per-user/global activity. Administrator-controlled accounts, TOTP, revocable sessions, idle/absolute expiry, password changes, operator recovery, CSRF and database-backed limits.
- Owner-only assessments, search, reviewed evidence, PDFs, consent records and activity events.
- Bounded static x86/x64 PE inspection. Uploaded programs are never executed.
- AES-256-GCM documents, RSA-OAEP SHA-256 key wrapping, PNG embedding, authenticated recovery and automatically assigned RSA-3072 account keys in an encrypted local vault. Owners view/copy/download public keys and view an encrypted private PEM or download the same pair after fresh password/TOTP verification.
- Separate VirusTotal workspace: MD5/SHA-1/SHA-256 lookup, URL submission, public IPv4/IPv6 reputation, and arbitrary file extensions up to 20 MiB. Disclosure consent, private history/search/filter, engine findings, report timestamps, refresh and JSON export.
- Durable provider jobs with shared quotas, bounded retries/polling, leases and hard process deadlines. API keys remain on the server. The optional reputation step on local PE assessments still sends only the SHA-256.
- Local OpenBin web upload/download and operator CLI, using a Ghidra adapter with network disabled, RAM-backed scratch space, bounded concurrency and local provenance. Direct Docker and a dedicated WSL 2 engine are supported.
- Versioned migration, staged SQLite restore, verified backups, operations/readiness screens, restricted local files and bounded logs.

The **Local AI** workspace automatically connects OpenBin/Ghidra extraction to local Qwen3 inference, evidence validation, private history, cancellation, progress and JSON/PDF reports. Its model/runtime use a separately configured local directory (D: on the development workstation). See [local AI setup and evaluation](docs/LOCAL_AI.md). The original supervised import and raw decompilation workflows remain available. No trained malware classifier or measured detection accuracy is claimed. No findings or no provider detections does not establish safety.

## Operator commands

```powershell
.venv\Scripts\python run.py create-admin
.venv\Scripts\python run.py create-user
.venv\Scripts\python run.py doctor
.venv\Scripts\python run.py backup
.venv\Scripts\python -m pytest -q
node --test tests/document-progress.test.cjs tests/analysis-updates.test.cjs tests/analysis-updates-ui.test.cjs tests/ai-ui.test.cjs
.venv\Scripts\python tools/package_source.py
```

Doctor checks operational prerequisites and image presence, not successful processing or security certification.

Protect and Recover show an animated processing bar, then **Download started** when the server sends the attachment. This confirms file preparation, not completion of the browser's disk save. The optional Node command above checks the client progress logic; Node is not required to run the application.

The top-bar **Updates** button lists active and recent file, URL, IP and hash checks. Click an alert to open its result. Completed analyses, unknown reports and failed/unfinished checks have distinct labels. Updates read only the local database and do not spend provider quota.

## Data and limits

The web app retains accounts, scan metadata/results, submitted indicators/URLs/filenames, consent, jobs and activity. Upload bytes and uploaded private-key files are not persisted locally. Assigned public keys and passphrase-encrypted private keys are retained in the account vault; its wrapping passphrase is derived from the original server secret and account ID. **External File upload sends the entire file to VirusTotal; other external modes send their indicator.** VirusTotal may retain/share submissions. Do not submit confidential data. The separate decompiler saves JSON to the operator-selected local path. Metadata backups remain until the operator removes them.

This is a trusted-server design, not end-to-end encryption. Protect the OS account, disks, backups and document keys. Physical memory erasure is not guaranteed. Do not expose this loopback application through a tunnel or public proxy.

Limits: complete request below 28 MiB; 20 MiB external upload; 10 MiB native PE; 5 MiB document subject to PNG capacity; PNG 22 MiB / 12 million pixels; PEM key files 16 KiB; RSA 2048–4096 bits. Protect/recover checks selected file sizes before upload when JavaScript is enabled; server limits remain enforced independently. Provider engines may not support every file format. LSB hiding is detectable and fragile: resizing or altering a protected PNG can prevent recovery. Account recovery preserves access to the existing assigned vault key. Lost external key files, export passphrases or the original vault secret cannot be reconstructed.

Read [user guide](docs/USER_GUIDE.md), [OpenBin contract](docs/OPENBIN_IMPORT.md), [third-party record](docs/THIRD_PARTY.md), and [academic evaluation](docs/EVALUATION.md). The original requirements analysis remains historical project context.
