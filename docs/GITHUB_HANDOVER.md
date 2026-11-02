# GitHub client handover

GitHub distributes the source code. The application continues to run on the client's own Windows computer at `http://127.0.0.1:5050`; no hosting is required. A private repository requires the client's GitHub account to have access.

## First installation

1. Install Git, Python 3.12, PowerShell 7, and WSL 2 (or an existing supported Docker Linux-container engine). The verified machine has 16 GB RAM. Allow sufficient disk space for the Python environment, WSL, Docker images and the approximately 2.5 GB Qwen3 model. Initial setup needs internet.
2. Clone the repository and install the Python dependencies:

   ```powershell
   git clone https://github.com/Muhammadahmer786/Sharafatproject-.git sentinel-lab
   cd sentinel-lab
   py -3.12 -m venv .venv
   .venv\Scripts\python -m pip install -r requirements.lock.txt
   Copy-Item -LiteralPath .env.example -Destination .env
   .venv\Scripts\python run.py migrate
   ```

3. Follow [Local deployment](LOCAL_DEPLOYMENT.md) to install the Docker/OpenBin workers. For the bundled WSL route, set `SENTINEL_WSL_DISTRO=SentinelLab` in `.env` after installing that distribution. Run PowerShell scripts with PowerShell 7, for example `pwsh -NoProfile -File tools/setup-workers.ps1 -IncludeOpenBin`.
4. Follow [Local AI setup](LOCAL_AI.md) to install Ollama and pull Qwen3. The default runtime directory is `D:\SentinelRuntime\ai`. If the client has no D: drive, choose a suitable directory, pass it to the setup tools and set the same `LOCAL_AI_RUNTIME_DIR` in `.env`.
5. Configure the client's provider key, create an administrator and secure local state:

   ```powershell
   .venv\Scripts\python tools/configure-virustotal.py
   .venv\Scripts\python run.py create-admin
   pwsh -NoProfile -File tools/secure-local-files.ps1
   .venv\Scripts\python run.py
   ```

   VirusTotal configuration is needed only for external checks. The client chooses their administrator credentials privately. Keep the server terminal open, sign in at `http://127.0.0.1:5050`, and enroll the administrator's authenticator in Account security.

6. From a second terminal in the same folder, check setup:

   ```powershell
   .venv\Scripts\python tools/check_workers.py --include-openbin
   .venv\Scripts\python run.py doctor
   ```

   Use the included inert `examples/synthetic-demo.exe` to verify the Local AI workflow. It is a parsing fixture; do not execute it. A completed fixture scan verifies operation, not malware-detection accuracy.

Only copy `.env.example` on first installation. Existing `.env`, `instance/.secret`, databases and account keys must be preserved. The repository deliberately has no shared login or provider API key.

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
