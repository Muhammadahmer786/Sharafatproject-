# Client setup: download, install and run Sentinel Lab on Windows

Follow this guide on the **client's computer** for a new installation. The project runs locally at **http://127.0.0.1:5050**. GitHub supplies the code; it does not host the application or install its dependencies.

**Repository:** [Muhammadahmer786/Sharafatproject-](https://github.com/Muhammadahmer786/Sharafatproject-). If the repository is private, the owner must invite the client's GitHub account and the client must accept that invitation first.

Read the requirements and choose a Docker route before starting. Run each command in order, wait for it to finish, and **stop if it reports an error**. Commands below are for PowerShell, not Command Prompt. Unless a step says otherwise, use the same normal Windows account throughout. Do not copy the developer's `.env`, `.venv`, database or account keys.

## Contents

1. [System requirements](#1-system-requirements)
2. [Install the basic tools](#2-install-the-basic-tools)
3. [Clone or download the project](#3-clone-or-download-the-project)
4. [Prepare Python and configuration](#4-prepare-python-and-configuration)
5. [Install a Docker engine](#5-install-a-docker-engine)
6. [Install the document and OpenBin workers](#6-install-the-document-and-openbin-workers)
7. [Install the local AI runtime and model](#7-install-the-local-ai-runtime-and-model)
8. [Configure VirusTotal](#8-configure-virustotal)
9. [Create an administrator and sign in](#9-create-an-administrator-and-sign-in)
10. [Verify every main workflow](#10-verify-every-main-workflow)
11. [Start and stop on later days](#11-start-and-stop-on-later-days)
12. [Back up and update safely](#12-back-up-and-update-safely)
13. [Troubleshooting](#13-troubleshooting)

## 1. System requirements

These are practical planning requirements for running **all features**, including local Qwen3 inference. The existing verified workstation has 16 GB RAM; this is not a benchmark proving a minimum for every file or workload.

| Item | Plan for |
| --- | --- |
| Operating system | A currently serviced **Windows 11, 64-bit Intel/AMD** installation. These installers target x64, not Windows ARM, macOS or Linux hosts. |
| Processor | 64-bit Intel/AMD CPU, at least 2 cores; 4 or more modern cores recommended. Hardware virtualization and SLAT support are needed for WSL 2/Docker. |
| Memory | **16 GB RAM** for the documented small-workload configuration; **32 GB recommended** for more headroom. Close other memory-heavy applications during AI analysis. |
| Storage | Plan for **40 GB free on an SSD** for the full initial setup and working room. This is an allowance, not a fixed download size; Docker storage, caches, models and backups grow. Keep free space on C: even when runtimes are on another drive. |
| Graphics | A dedicated GPU is **not required**. The supplied runtime launcher uses CPU inference. Larger analyses may take several minutes. |
| Internet | Required for cloning, Python packages, Docker images, OpenBin, Ollama and model downloads. Required whenever using VirusTotal. Installed local document/OpenBin/AI workflows do not require a cloud API. |
| Permissions | Ability to install software and enable Windows virtualization/WSL features. Run the application afterward as the same normal Windows operator. |
| Browser | A current Edge, Chrome or Firefox on the same PC. |
| Authenticator | A TOTP authenticator app for the administrator's two-step verification. Keep both PC and authenticator clocks accurate. |

Check **Settings → System → About** for Windows, processor and installed RAM. Open **Task Manager → Performance → CPU** and check **Virtualization: Enabled**. If disabled, enable Intel VT-x/AMD-V in the PC's firmware using its manufacturer's instructions. In File Explorer, open **This PC** to check available disk space.

Docker Desktop has its own Windows servicing and WSL requirements; check its [current Windows installation requirements](https://docs.docker.com/desktop/setup/install/windows-install/). Do not assume an old Windows build is supported just because this application starts on it.

### What needs installing

| Component | Purpose | How it is installed |
| --- | --- | --- |
| Git | Clone and receive future updates | Step 2; optional only for ZIP installs |
| Python 3.12, 64-bit | Run the web application and setup tools | Step 2 |
| PowerShell 7 (`pwsh`) | Run the supplied setup scripts | Step 2 |
| Python packages | Flask, document processing and other dependencies | Locked dependency file in step 4 |
| Docker Linux-container engine | Isolate key generation, document processing and binary parsing | Choose one route in step 5 |
| Document/PE worker and OpenBin/Ghidra worker | Document protection/recovery and local analysis | Step 6 |
| Ollama + `qwen3:4b` | Local AI inference after OpenBin extraction | Step 7 |
| VirusTotal account/API key | External hash, URL, IP and file checks | Optional step 8; required for those external checks |
| SQLite | Local accounts, history, jobs and metadata | Included with Python; created automatically |

You do **not** need Node.js, a separate Java installation, MySQL, an OpenAI key or an OpenBin cloud account for the documented application setup. Ghidra and its Java runtime run inside the worker image. Node is only used for developer tests. The supplied Compose file is an optional MySQL service, **not** a command that launches the complete project.

### Choose the storage and Docker route

| Your PC | Follow |
| --- | --- |
| Has D: (or another non-system data drive), no existing WSL configuration, and you want the bundled dedicated engine | **Route A:** dedicated `SentinelLab` WSL distribution. This is the route used on the existing verified workstation. |
| Has only C:, already uses Docker Desktop, or already has a WSL setup you want to retain | **Route B:** Docker Desktop with Linux containers. For C:-only AI storage, use the manual pinned runtime instructions in step 7. |

The bundled WSL installer refuses the Windows system drive; the bundled AI installer refuses C:. **Changing their `--directory` to C: will not work.** Route B below explains the alternative. Do not install both Docker routes for this project.

Examples use a project folder under your Windows profile and runtime storage at `D:\SentinelRuntime` or `C:\SentinelRuntime`. If using E: or another location, substitute it consistently in commands and `.env`.

## 2. Install the basic tools

1. Install [Git for Windows](https://git-scm.com/install/windows), choosing the 64-bit version. The normal installer defaults are suitable.
2. Install the official [Python install manager](https://www.python.org/downloads/), then open a **new** PowerShell window and install the standard Python 3.12 runtime:

   ```powershell
   pymanager install 3.12
   py -3.12 --version
   ```

   The second command must show `Python 3.12.x`. If Python 3.12 is already installed, you can skip its installation. `pymanager` avoids conflicts with an older `py` launcher; see the [official Windows Python instructions](https://docs.python.org/3/using/windows.html). Use a standard 64-bit runtime, not the embeddable package or a different Python major/minor version.

3. Install [PowerShell 7 for Windows](https://learn.microsoft.com/en-us/powershell/scripting/install/install-powershell-on-windows). It installs alongside Windows PowerShell 5.1; its command is `pwsh`.
4. Close the terminal, open **PowerShell 7** from Start, and verify:

   ```powershell
   git --version
   py -3.12 --version
   pwsh --version
   ```

Continue only when all three commands work. There is no need to activate a virtual environment or change the machine-wide PowerShell execution policy for the Python commands in this guide.

## 3. Clone or download the project

### Option 1: Git clone — recommended for easy updates

In a normal PowerShell window:

```powershell
New-Item -ItemType Directory -Path "$env:USERPROFILE\Projects" -Force | Out-Null
Set-Location -LiteralPath "$env:USERPROFILE\Projects"
git clone https://github.com/Muhammadahmer786/Sharafatproject-.git sentinel-lab
Set-Location -LiteralPath .\sentinel-lab
Test-Path -LiteralPath .\run.py
```

The last command must show **True**. If Git requests authentication, sign in with the GitHub account that has repository access. Your GitHub password is not the application's login password. Do not put tokens into the clone URL. See [GitHub's cloning guide](https://docs.github.com/en/repositories/creating-and-managing-repositories/cloning-a-repository) for authentication assistance.

If `sentinel-lab` already exists, inspect it first. Use [the update procedure](#12-back-up-and-update-safely) for an existing installation instead of cloning over it.

### Option 2: Download ZIP

1. Open the [repository](https://github.com/Muhammadahmer786/Sharafatproject-) in your browser and sign in if it is private.
2. Select **Code → Download ZIP**.
3. Right-click the downloaded ZIP → **Extract All**. Do not run the application inside the compressed folder.
4. Find the extracted folder containing `run.py`, `requirements.lock.txt`, `sentinel` and `tools`. Rename that folder `sentinel-lab` and put it in your Windows profile's `Projects` folder. Avoid OneDrive/shared folders for the live database.
5. In PowerShell, enter that folder and check it:

   ```powershell
   Set-Location -LiteralPath "$env:USERPROFILE\Projects\sentinel-lab"
   Test-Path -LiteralPath .\run.py
   ```

A ZIP download has no Git history, so **`git pull` will not work in it**. Choose clone if the client wants simple future updates.

From now on, run project commands inside the folder containing `run.py`. All relative paths below start there.

## 4. Prepare Python and configuration

Run these commands **one at a time**:

```powershell
py -3.12 -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
```

Wait for dependency installation to finish without errors. Then create the private configuration only if it does not already exist:

```powershell
if (-not (Test-Path -LiteralPath .env)) {
    Copy-Item -LiteralPath .env.example -Destination .env
}
notepad .env
```

Keep these defaults:

```dotenv
SECRET_KEY=
ALLOW_REGISTRATION=0
PE_WORKER_MODE=docker
COOKIE_SECURE=0
LOCAL_AI_URL=http://127.0.0.1:11434
LOCAL_AI_MODEL=qwen3:4b
LOCAL_AI_TIMEOUT=600
OPENBIN_WORKER_IMAGE=sentinel-openbin-worker:local
```

Leave the MySQL settings empty; this guide uses SQLite. Set `SENTINEL_WSL_DISTRO` in step 5 and `LOCAL_AI_RUNTIME_DIR` in step 7. Save as **`.env`**, not `.env.txt`, and close Notepad.

```powershell
.venv\Scripts\python.exe run.py migrate
```

This initializes the local database/schema. With blank `SECRET_KEY`, the application uses a generated secret in `instance/.secret`. **Preserve that original secret** with this installation: replacing it prevents recovery of existing encrypted account keys and authenticator enrollments. Do not share `.env` or `instance` on GitHub.

## 5. Install a Docker engine

### Route A: dedicated WSL engine on D: or another data drive

Use this route only if there is no existing `SentinelLab` distribution or `%USERPROFILE%\.wslconfig`. The installer refuses to overwrite them. It creates a global WSL configuration limiting WSL to **6 GB RAM, 2 processors and no swap**; these settings also affect other WSL distributions. If you already use WSL, prefer Route B or ask your operator to reconcile the settings deliberately.

1. Open **PowerShell as Administrator** only for enabling/updating WSL:

   ```powershell
   wsl --install --no-distribution
   wsl --update
   wsl --set-default-version 2
   ```

   Restart Windows if requested, then finish any remaining commands. Do not continue while a reboot is pending. Existing WSL users can check `wsl --version` first. See [Microsoft's WSL installation guide](https://learn.microsoft.com/en-us/windows/wsl/install).

2. Close the administrator terminal. Open normal PowerShell as the Windows account that will run Sentinel Lab, return to the project folder, and run:

   ```powershell
   Set-Location -LiteralPath "$env:USERPROFILE\Projects\sentinel-lab"
   .venv\Scripts\python.exe tools/install-wsl-runtime.py --directory D:\SentinelRuntime --distro SentinelLab
   ```

   Allow at least **12 GiB free** on this target drive at the start. The installer downloads and verifies Ubuntu 24.04, imports it into `D:\SentinelRuntime\wsl`, and installs Docker Engine from Docker's repository. Initial setup can take a while. Do not rerun blindly if a partial install has already created the distribution.

3. In `.env`, set:

   ```dotenv
   SENTINEL_WSL_DISTRO=SentinelLab
   ```

4. Verify the engine:

   ```powershell
   wsl --list --verbose
   wsl -d SentinelLab -u root --exec systemctl start docker
   wsl -d SentinelLab -u root --exec docker info --format '{{.OSType}}'
   ```

   Expect `SentinelLab` with **VERSION 2**, and the final command to print **linux**. A Windows `docker` command is not required for this route; the project invokes Docker through WSL. Continue to step 6.

### Route B: Docker Desktop, including C:-only computers

1. Install the Windows x86_64 version from [Docker Desktop's official installation page](https://docs.docker.com/desktop/setup/install/windows-install/). Follow its WSL 2 prerequisite steps and reboot when requested. Check the vendor's subscription terms for your organization's use.
2. Open Docker Desktop. Use its **WSL 2 engine and Linux containers**, and wait until the engine is running. Do not select Windows containers.
3. Open a new normal PowerShell window, return to the project folder, and check:

   ```powershell
   docker version
   docker info --format '{{.OSType}}'
   ```

   `docker version` must show a reachable **Server**, and the last command must print **linux**.
4. In `.env`, leave the dedicated distro setting empty:

   ```dotenv
   SENTINEL_WSL_DISTRO=
   ```

Keep Docker Desktop running whenever using the application. Do not run the dedicated WSL installer as well.

## 6. Install the document and OpenBin workers

The Docker engine from step 5 must be running. These workers are needed **before creating accounts**, because account creation generates the assigned key pair in the isolated document worker.

If using D: for runtime storage:

```powershell
pwsh -NoProfile -File .\tools\setup-workers.ps1 -IncludeOpenBin -CacheDirectory "D:\SentinelRuntime\downloads"
```

For a C:-only PC, use this command **instead**:

```powershell
pwsh -NoProfile -File .\tools\setup-workers.ps1 -IncludeOpenBin -CacheDirectory "C:\SentinelRuntime\downloads"
```

This builds `sentinel-pe-worker:local`, downloads the pinned official OpenBin Ghidra image archive, verifies its checksum, loads it and builds `sentinel-openbin-worker:local`. The Ghidra archive alone is about 632 MiB; image layers and extraction need additional space. The build tool requires at least 6 GiB free in its cache location. Internet is needed for this first build.

Verify actual worker operations:

```powershell
.venv\Scripts\python.exe tools/check_workers.py --include-openbin
```

Expect passing checks for static inspection, key generation/document round-trip, and offline OpenBin decompilation. This check uses an inert fixture and does not execute uploaded programs. If it fails, resolve the worker issue before creating accounts or using Protect/Recover.

**OpenBin clarification:** this web application uses OpenBin's local Ghidra extraction and its own local Ollama adapter. `tools/install-openbin.ps1` installs additional upstream OpenBin/BINNY command-line tools and is **optional**, not a missing dependency for the web workflow. BINNY requires upstream authentication; the upstream `openbin decompile` command is not the offline pipeline documented here. See [third-party components](THIRD_PARTY.md).

## 7. Install the local AI runtime and model

This step enables **Local AI**. It needs both the OpenBin worker and an installed local model. The pinned runtime is **Ollama 0.40.13**, with **`qwen3:4b`**, whose model weights are approximately [2.5 GB](https://ollama.com/library/qwen3:4b). The runtime ZIP is another approximately 1.5 GiB, before extraction. Model files are not included in GitHub.

If another Ollama installation already listens on port 11434, identify it first. The launcher reuses an existing listener, which may have a different model directory/configuration. To use this guide's portable runtime consistently, exit your own existing Ollama tray/server before the initial setup; do not stop an unrelated service without checking with its operator.

### With D: or another non-C: data drive

```powershell
.venv\Scripts\python.exe tools/install-local-ai.py --directory "D:\SentinelRuntime\ai"
pwsh -NoProfile -File .\tools\start-local-ai.ps1 -RuntimeDirectory "D:\SentinelRuntime\ai" -PullModel
```

The installer checks the pinned archive checksum and needs at least 9 GiB free when downloading a new runtime archive. Wait for the model pull to complete successfully. In `.env`, set:

```dotenv
LOCAL_AI_RUNTIME_DIR=D:/SentinelRuntime/ai
```

For another data drive, change **both commands and `.env`**. `start-local-ai.ps1` defaults to D: and does not read the directory from `.env`; always pass `-RuntimeDirectory` when using another location.

### With only C: — manual installation of the same pinned runtime

The bundled Python AI installer rejects C:. The following explicit manual procedure uses the same official ZIP and checksum at a path the application's runtime manager supports. It has been checked against the installer/runtime code; it has not been validated by rebuilding a fresh C:-only client PC.

Open **PowerShell 7**, in the project folder. Ensure the full setup has the disk allowance in step 1. Run this entire block once; it stops if the target runtime already exists or the download checksum differs:

```powershell
$ErrorActionPreference = 'Stop'
$sentinelAiRoot = 'C:\SentinelRuntime\ai'
$sentinelAiTarget = Join-Path $sentinelAiRoot 'ollama-0.40.13'
$sentinelAiArchive = Join-Path $sentinelAiRoot 'ollama-0.40.13.zip'
if (Test-Path -LiteralPath $sentinelAiTarget) {
    throw 'The runtime directory already exists. Inspect that installation before continuing.'
}
New-Item -ItemType Directory -Path $sentinelAiRoot -Force | Out-Null
if (-not (Test-Path -LiteralPath $sentinelAiArchive)) {
    Invoke-WebRequest -Uri 'https://github.com/ollama/ollama/releases/download/v0.40.13/ollama-windows-amd64.zip' -OutFile $sentinelAiArchive
}
$sentinelAiHash = (Get-FileHash -LiteralPath $sentinelAiArchive -Algorithm SHA256).Hash
if ($sentinelAiHash -ne '7afa38624fa62ee5d8293422d0ab084c1bb4603134c7f4dafce11a033b57cc19') {
    throw 'Ollama checksum mismatch. Do not extract or run this download.'
}
Expand-Archive -LiteralPath $sentinelAiArchive -DestinationPath $sentinelAiTarget
foreach ($sentinelAiFolder in @('models', 'tmp', 'logs')) {
    New-Item -ItemType Directory -Path (Join-Path $sentinelAiRoot $sentinelAiFolder) -Force | Out-Null
}
if (-not (Test-Path -LiteralPath (Join-Path $sentinelAiTarget 'ollama.exe'))) {
    throw 'ollama.exe is missing. Check the extracted directory.'
}
```

If your Windows account cannot create `C:\SentinelRuntime`, use an operator-owned local directory and substitute its absolute path consistently; do not run the whole application as Administrator to work around folder permissions. A failed/interrupted download may leave an incomplete ZIP. On retry, inspect/remove only that failed ZIP before downloading again; never bypass the hash check or overwrite an existing runtime blindly.

Set `.env`:

```dotenv
LOCAL_AI_RUNTIME_DIR=C:/SentinelRuntime/ai
```

Then start the pinned portable server and download the model:

```powershell
pwsh -NoProfile -File .\tools\start-local-ai.ps1 -RuntimeDirectory "C:\SentinelRuntime\ai" -PullModel
```

### Check the model — either route

```powershell
(Invoke-RestMethod -Uri 'http://127.0.0.1:11434/api/tags').models | Select-Object name
```

Expect **`qwen3:4b`**. Keep `LOCAL_AI_URL=http://127.0.0.1:11434` and `LOCAL_AI_MODEL=qwen3:4b` in `.env`. The model pull is an initial download, not a step for every launch. Ordinary application startup starts/monitors the installed portable runtime when needed but **never downloads missing models**. No OpenAI or hosted OpenBin key is needed.

## 8. Configure VirusTotal

Skip this step only if you do not need external hash, URL, IP or file checks. Local protection/recovery, OpenBin and local AI work without a VirusTotal key.

1. Obtain the **client's own** API key from their [VirusTotal account](https://www.virustotal.com/). Use a plan licensed for the intended use; the [Public API terms](https://docs.virustotal.com/reference/public-vs-premium-api) restrict commercial use. A shared developer key is not included.
2. From the project folder, run:

   ```powershell
   .venv\Scripts\python.exe tools/configure-virustotal.py
   ```

3. Paste the key into the hidden prompt and press Enter. It is stored in private `.env`, not in source code. If the web server is already running, stop and restart it to load the change.

The application currently shares one request per 16 seconds and a maximum of 500 per UTC day across users. A paid key alone does not change these application limits. Queued checks can take time. External File mode sends the **whole file** to VirusTotal; URL mode sends the full URL. Use authorized, non-confidential test data and the displayed consent controls.

## 9. Create an administrator and sign in

The Docker engine and document worker must already pass step 6. In the project folder:

```powershell
.venv\Scripts\python.exe run.py create-admin
```

Enter an account email, display name, unique password and matching password confirmation. Passwords must be **12–128 characters** and do not display while typing. The email is a local account identifier; the app does not send email. There is **no default email/password**. Save the credentials privately. Account creation assigns that user's public/private key pair automatically.

Restrict private configuration/state to the operating Windows account and local system administrators, then start:

```powershell
pwsh -NoProfile -File .\tools\secure-local-files.ps1
.venv\Scripts\python.exe run.py
```

Keep this terminal open. Open **[http://127.0.0.1:5050](http://127.0.0.1:5050)** in the same PC's browser and sign in with the credentials you just created.

### Enroll administrator two-step verification

1. Open **Workspace settings → Account security → Two-step verification**.
2. Enter the current password and choose **Set up authenticator**.
3. Add a new **time-based/TOTP account manually** in your authenticator using the displayed secret. The application provides a text secret, not a QR-code setup flow. Keep it private.
4. Enter the current six-digit code and choose **Confirm authenticator**.
5. Sign in again if the session is revoked; use the next fresh authenticator code. A code already used is not reusable.

The administrator workspace requires this enrollment and verified sign-in. Enable automatic date/time on both devices if codes fail.

### Add client users

An enrolled administrator can open **Admin workspace → Accounts → Add an account**, enter the user's name/email, and create it. Give the displayed **single-use, 30-minute setup code** privately to that user. They open **Recover your account** from the login page, enter their email/code and choose a password. There is no email delivery service.

Alternatively, the Windows operator can run `.venv\Scripts\python.exe run.py create-user` and follow its hidden password prompts. Keep public registration disabled. Users access their own history and assigned keys; they do not receive other users' private keys. Private-key export requires fresh authentication and a separate backup passphrase; keep that exported encrypted key and passphrase safe.

## 10. Verify every main workflow

Leave the server terminal running. Open a **second** normal PowerShell window and run:

```powershell
Set-Location -LiteralPath "$env:USERPROFILE\Projects\sentinel-lab"
.venv\Scripts\python.exe run.py backup
.venv\Scripts\python.exe run.py doctor
```

After workers/model are available, public registration is closed, the administrator has enrolled MFA and a recent backup exists, expect doctor status **`ready`**. It checks setup/readiness, not VirusTotal key validity, AI accuracy or every processing operation. `/health` is a liveness endpoint; `/ready` may return 503 until prerequisites pass.

Complete these browser checks using your own account:

| Feature | Check | Success looks like |
| --- | --- | --- |
| Login/account | Sign out and sign in with password/TOTP | Your own workspace opens |
| Assigned keys | Open Encryption keys, view the public key, authenticate for an encrypted private-key backup | Assigned pair is available; export downloads |
| Protect | Choose `examples/sample-document.txt`, `examples/cover.png`, and your assigned account key | A protected PNG downloads after processing |
| Recover | Upload that protected PNG and use the corresponding account key/authentication | The original text file downloads and matches its original content |
| Static file analysis | Upload `examples/synthetic-demo.exe` | A static report is produced |
| Local OpenBin | Upload the same inert fixture | Local decompilation result/JSON downloads |
| Local AI | Upload the fixture on Local AI and wait for the queued stages | A completed report opens and JSON/PDF exports download |
| Threat intelligence | With the client's API key, test an authorized public hash, URL, IP and non-confidential small file | Results or explicit provider statuses appear; pending items are linked in Updates |
| Administration | Create an ordinary user and inspect account/activity controls | User gets their own workspace/key pair; administrator can view account activity |

`examples/synthetic-demo.exe` is an **inert parsing fixture**. Do not double-click or execute it. A successful fixture run verifies the pipeline; it does not establish malware-detection accuracy. The AI report is evidence for review, not a safety certificate.

For Protect/Recover, the UI's **Download started** status means the file was prepared and handed to the browser. Check the browser's Downloads panel for the saved file. PNG capacity limits the document size; use the supplied tiny document/cover for the first check. Preserve protected PNGs unchanged—resizing or lossy conversion can break recovery.

If one check fails, use the table below and the detailed [operator runbook](LOCAL_DEPLOYMENT.md). Do not consider a successful login alone proof that all workers/model/provider features are installed.

## 11. Start and stop on later days

You do not need to clone, reinstall packages or pull the model each day.

1. **Start your Docker route.** For Desktop, open Docker Desktop and wait for its engine. For the dedicated WSL route:

   ```powershell
   wsl -d SentinelLab -u root --exec systemctl start docker
   ```

2. Open normal PowerShell, enter the project folder and start the app:

   ```powershell
   Set-Location -LiteralPath "$env:USERPROFILE\Projects\sentinel-lab"
   .venv\Scripts\python.exe run.py
   ```

3. Keep the terminal open and visit **http://127.0.0.1:5050**. The application starts the installed portable Ollama runtime if its configured endpoint is not already listening.
4. To stop, return to that terminal, press **Ctrl+C**, and wait for shutdown. Do not start multiple copies against the same database.

Optional foreground restart supervision: use `pwsh -NoProfile -File .\start.ps1 -Supervise` **instead of** the Python launch command. No Windows service, background login task or hosting is installed. Restart manually after Windows restarts. A model server started separately by `start-local-ai.ps1` can remain running after the app stops; the app only shuts down a model process it started itself.

The address `127.0.0.1` means **this PC**. Another PC/phone cannot access this installation using that address. This guide does not configure LAN sharing or public hosting.

## 12. Back up and update safely

### Backups

Run `.venv\Scripts\python.exe run.py backup` from the project folder. Database snapshots are written under `instance/backups`. The app also checks for a daily snapshot, but no automatic deletion/retention policy is configured.

Keep a protected copy of the database backup **and the original `instance/.secret` (or configured `SECRET_KEY`)**, plus private configuration, on a separate secure disk. The database alone cannot unlock existing account key vaults. Owners should also retain encrypted private-key exports and their separate passphrases. Never upload any of these files to GitHub.

Runtime/model directories can be downloaded again; account keys, the original server secret and customer history cannot be recreated from GitHub. See [backup and restore instructions](LOCAL_DEPLOYMENT.md#backups-and-restore) before restoring or moving an existing installation to another PC. A fresh client setup creates new accounts/keys; it does not import the developer's users.

### Updates for a cloned installation

Read update notes. Press **Ctrl+C** in the server terminal and wait for shutdown. In the project folder, run these commands one at a time:

```powershell
.venv\Scripts\python.exe run.py backup
git status --short
```

If Git lists local source changes, preserve/review them before continuing. Otherwise:

```powershell
git pull --ff-only
.venv\Scripts\python.exe -m pip install -r requirements.lock.txt
.venv\Scripts\python.exe run.py migrate
.venv\Scripts\python.exe run.py
```

Stop on any error. Do not overwrite `.env`, `.secret` or the database, and do not force updates with a hard reset. If an update changes Dockerfiles, worker dependencies or the selected model, follow its rebuild/download notes. Run `run.py doctor` in a second terminal and repeat the affected workflow checks after restarting.

For ZIP installations, `git pull` is unavailable. Use a fresh source directory and the documented protected backup/restore process when updating; do not replace the live installation folder blindly. Prefer a Git clone from the beginning for ongoing handover.

## 13. Troubleshooting

| Problem | What to check/do |
| --- | --- |
| GitHub shows 404 or permission denied | Confirm the exact repository URL, accept the owner's invitation if private, and authenticate with the invited GitHub account. |
| `git`, `pwsh` or `py` not recognized | Finish step 2, then open a new terminal. For Python install-manager/old-launcher conflicts, use `pymanager exec -V:3.12 --version` and its equivalent `-m venv .venv` command. |
| Cannot find `run.py` or `.venv\Scripts\python.exe` | Enter the actual extracted/cloned folder containing `run.py`; complete step 4. A ZIP may have an extra containing folder. |
| Python packages fail to install | Confirm Python 3.12 x64, internet access and free space. Use the supplied locked requirements; capture the final error without secrets. Do not switch Python versions randomly. |
| Downloaded PowerShell script is blocked | Inspect/trust the script first; for a ZIP download, unblock the specific trusted file, for example `Unblock-File -LiteralPath .\tools\setup-workers.ps1`, then retry. Organization-enforced script policy needs the local administrator; do not globally disable it. |
| WSL asks for virtualization or restart | Enable hardware virtualization, complete Microsoft's WSL prerequisites and reboot when requested. Check `wsl --version`/`wsl --list --verbose`. |
| Dedicated WSL installer refuses existing distro or `.wslconfig` | It deliberately preserves existing configuration. Inspect/reuse it with operator assistance or use Route B. Do not unregister a distro or delete its disk to force setup. |
| Installer says to choose a data drive | The WSL/system-drive and AI/C: restrictions are real. Use a non-system drive or the Desktop plus manual AI route in this guide. |
| Docker not reachable / wrong container OS | Start the selected engine; verify `linux`. Check `.env`: `SentinelLab` for dedicated WSL, blank for Desktop. Use the Windows account owning the distro. |
| Account creation, Protect or Recover reports missing worker | Finish step 6 and pass `check_workers.py`. Key creation also needs Docker. Do not change to native mode to hide the setup failure. |
| OpenBin image missing | Rerun worker setup with `-IncludeOpenBin` after checking space/connectivity. The optional BINNY download does not build this worker. |
| Model absent or AI unavailable | Check `.env` runtime path, port 11434 and `/api/tags`; use `start-local-ai.ps1 -RuntimeDirectory <your-path> -PullModel` with your actual path. The launcher does not read that path from `.env`. |
| AI runtime checksum mismatch | Do not run/extract the archive. Inspect the failed download and retry from the pinned official URL; never remove the checksum check. |
| AI analysis is slow or times out | CPU inference can take minutes. Close other heavy programs and try the tiny included fixture. Check runtime `logs` and `instance/logs`; a failed result is not a completed malware verdict. |
| Site will not open | Keep the server terminal running, inspect its error, and use `http://127.0.0.1:5050` on the same PC. If another service owns 5050, run `run.py --port 5051` and use that port; do not run a second Sentinel instance. |
| No login credentials / forgot password | There is no shipped default. Create the admin in step 9. For an existing account, the local operator uses `run.py reset-password --email person@example.test`, substituting the actual email, then gives the one-time code privately. |
| Admin access blocked / doctor needs MFA | Enroll the administrator's authenticator and sign in with a fresh code. All active admin accounts must be enrolled for readiness. |
| Invalid authenticator code | Check automatic time/date and use the next code; a used code cannot be reused. Operator-assisted MFA recovery is in the runbook. |
| VirusTotal unauthorized, quota exceeded or still pending | Check the client's key/plan, restart after configuration changes, and allow for shared quotas. Inspect the explicit status and Updates; not-found/failed/pending are different from a completed clean result. |
| Settings did not change after editing `.env` | Save the real `.env`, restart the server, and check for older environment variables inherited from the terminal; existing process variables take precedence. |
| Upload too large / document will not fit | Limits: entire request below 28 MiB, external file up to 20 MiB, PE up to 10 MiB, document up to 5 MiB subject to cover capacity, PNG up to 22 MiB/12 million pixels. Use a larger eligible lossless cover or smaller document. |
| Download not visible | Check the browser's Downloads panel and save prompt; wait for processing. Do not close the page mid-operation. |
| Doctor reports no recent backup | Run `run.py backup`, check free space/permissions, then doctor again. |
| Backup restores but keys cannot open | Confirm the original server secret was preserved. Do not generate a replacement; it cannot decrypt the old vault. |

When requesting support, provide the failing step, Windows version, command/error, chosen Docker route and redacted log excerpt. Do not include API keys, passwords, TOTP secrets, private keys or client documents.

## Where files live

| Location | Contents |
| --- | --- |
| Project folder | Downloaded source, documentation and setup scripts |
| Project `.venv` | This PC's Python environment; recreate from the lock file |
| Project `.env` | Private configuration and optional provider key |
| Project `instance` | Database, original secret, logs and database backups |
| `D:\SentinelRuntime\wsl` | Dedicated WSL/Docker disk for Route A only |
| Docker Desktop's configured storage | Docker images/data for Route B; managed by Desktop |
| Selected runtime `downloads` directory | OpenBin/Ghidra installation cache |
| Selected runtime `ai` directory | Portable Ollama, local model weights, temporary files and model logs |
| Browser-selected Downloads folder | Files/reports/keys the user explicitly downloads |

GitHub contains source and inert examples. It intentionally excludes accounts, keys, `.env`, `.venv`, model weights, Docker images and client data. Installing dependencies downloads additional data; downloading the source ZIP alone does not provide an offline installer.

## Further instructions and handover status

- [User guide](USER_GUIDE.md): using the workspaces.
- [Operator runbook](LOCAL_DEPLOYMENT.md): recovery, backups and operational limits.
- [Local AI](LOCAL_AI.md): pipeline, model behavior and evaluation.
- [GitHub handover](GITHUB_HANDOVER.md): source sharing and updates.
- [Verification record](VERIFICATION.md) and [remaining acceptance work](REMAINING_FEATURES.md): what has been checked and what still needs customer validation.

Guide checked against repository scripts and official prerequisite documentation on **3 November 2026**. Existing Windows/Python 3.12/dedicated WSL functionality has verification records. This documentation update does not claim that every alternative installation route has been freshly installed on the client's hardware. Complete step 10 on the actual client PC before accepting the handover.
