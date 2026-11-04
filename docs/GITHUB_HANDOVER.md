# GitHub client handover

GitHub distributes the source code. The application continues to run on the client's own Windows computer at `http://127.0.0.1:5050`; no hosting is required. A private repository requires the client's GitHub account to have access.

## First installation

**Quick route:** download/clone the complete project, extract it if zipped, and double-click **`Setup-and-Run.cmd`**. Or, with Python 3.12 installed, run `py -3.12 setup_client.py`. The launcher handles dependency installation and local worker/model setup. Follow its prompts, rerun after any required reboot, then enroll the administrator's authenticator in the browser. See [automatic setup](CLIENT_SETUP.md#automatic-setup--recommended).

**Send the client the [complete step-by-step setup guide](CLIENT_SETUP.md).** It explains system requirements, installing Git/Python/PowerShell, cloning or downloading a ZIP, Docker, OpenBin, local Ollama/Qwen3, VirusTotal configuration, administrator enrollment and checking every main workflow.

For operators choosing manual setup, the installation order is:

1. Check Windows x64, virtualization, RAM and storage requirements; install the basic tools.
2. Clone the repository (recommended for later updates), or extract its ZIP.
3. Create the Python environment, install locked dependencies and initialize private configuration/database.
4. Choose a dedicated WSL engine on a data drive, or Docker Desktop with Linux containers.
5. Build and verify the document/PE and OpenBin workers **before creating accounts**.
6. Install the local AI runtime and model; configure the client's own VirusTotal key if external checks are required.
7. Create the administrator, secure local files, start the server, enroll TOTP and complete the guide's workflow checks.

Individual runtime installers require `--allow-system-drive` to use C:; the automatic launcher supplies it when needed. The full guide also retains a Docker Desktop plus manual pinned AI runtime path for C:-only computers. Do not just substitute C: into the manual data-drive commands without their explicit option.

Only copy `.env.example` on first installation. Existing `.env`, `instance/.secret`, databases and account keys must be preserved. The repository deliberately has no shared login or provider API key. Initial downloads require internet; cloning alone does not install workers/models. [Local deployment](LOCAL_DEPLOYMENT.md) remains the detailed operations/recovery reference.

## Receive later updates

Read the release/update notes first. In the server terminal, press **Ctrl+C** and wait for shutdown. From the repository folder:

```powershell
.venv\Scripts\python run.py backup
git status --short
git pull --ff-only
.venv\Scripts\python -m pip install -r requirements.lock.txt
.venv\Scripts\python run.py migrate
.venv\Scripts\python run.py
```

If `git status` shows local source edits, resolve or preserve them before pulling. Stop if any command fails. Do not use a hard reset or overwrite `.env` to force an update. `git pull --ff-only` intentionally refuses divergent history. Keep a protected copy of the original application secret separately from database backups; both are needed to recover existing key vaults.

An update that changes worker images or the selected model may require rerunning the corresponding setup step described in its notes. Ordinary pulls do not download models or migrate a running application. After restarting, run `run.py doctor` in another terminal and verify the relevant workflows. See [remaining acceptance work](REMAINING_FEATURES.md).

## What belongs in GitHub

Commit application source, tests, setup scripts, documentation, `.env.example` and the inert examples. Keep `.env`, `instance/`, API keys, private keys, customer files, databases, logs, `.venv/`, `vendor/`, Docker images and model weights outside Git history. The supplied `.gitignore` covers these local files; inspect the staged files before publishing changes.

Repository access does not transfer application accounts or document keys. Client accounts and settings are created on the client's installation. Moving an existing instance is a separate protected backup/restore operation described in [Local deployment](LOCAL_DEPLOYMENT.md).
