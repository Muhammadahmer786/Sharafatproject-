# Local OpenBin AI analysis

The **Local AI** workspace (`/ai`) runs OpenBin's Ghidra extraction followed by actual local Ollama inference. It is an experimental static triage aid. It is not a trained malware classifier, antivirus certification, or a measured accuracy claim.

## Use

1. Log in and choose **Local AI** in the sidebar.
2. Select an authorized native x86/x64 Windows `.exe` or `.dll`, at most 10 MiB. Managed .NET files and other formats are outside this pipeline's scope. VirusTotal's separate workspace still supports other file extensions.
3. Confirm local-server access and select **Analyse locally**.
4. Follow the queued, inspection, decompilation, model analysis and validation stages. You can navigate elsewhere; **Updates** links to completion or failure. Cancel from the detail page if needed.
5. Open the report to inspect literal source quotations, coverage, model digest and limitations. Download JSON or PDF, revisit your private history, or delete a finished record.

Progress is a workflow milestone, not measured inference percentage. One job runs at a time, with a maximum of three outstanding submissions across users. A full queue asks you to wait. File bytes remain in memory and isolated container tmpfs. Selected evidence and reports persist in SQLite and its backups. Restarted jobs become interrupted and require resubmission; the application cannot resume raw bytes it does not retain.

## Runtime on this workstation

- Official portable Ollama **0.40.13**, installed under `D:\SentinelRuntime\ai\ollama-0.40.13`.
- Verified archive SHA-256: `7afa38624fa62ee5d8293422d0ab084c1bb4603134c7f4dafce11a033b57cc19`.
- Default **Qwen3 4B** quantized model, `qwen3:4b`, approximately 2.5 GB; the exact installed digest is recorded with every report.
- CPU inference on the i7-5600U; the integrated Intel GPU is not used. Expect minutes for larger evidence sets. The model is unloaded after each request.
- API binds `127.0.0.1:11434`. `OLLAMA_NO_CLOUD=1`, one parallel request, no model tools. Application requests bypass proxies and reject redirects, non-loopback endpoints and cloud model metadata.
- Model files, temporary runtime files and logs are on D:. No hosting or paid API key is needed. Initial runtime/model downloads require internet; inference uses installed local assets.

The application continues to offer a separate external VirusTotal workspace. That workspace requires explicit disclosure consent and internet; enabling local AI does not route its jobs to VirusTotal.

## Install / start

Run explicitly as the Windows account operating the application:

```powershell
.venv\Scripts\python tools/install-local-ai.py --directory D:/SentinelRuntime/ai
pwsh -NoProfile -File tools/start-local-ai.ps1 -PullModel
.venv\Scripts\python run.py
```

The installer uses the official pinned release and verifies its checksum before extraction. It never installs a Windows service, opens firewall ports or pulls models on ordinary application startup. `run.py` starts and monitors the installed runtime when the default endpoint is configured. It retries a stopped process with a 60-second backoff and stops only the runtime it started. A listener already using that port is left alone; the application's model check validates the actual service. For a reused Ollama service, its operator is responsible for its configuration; the application additionally rejects cloud model aliases and remote metadata. Download failures can be retried explicitly. A checksum failure needs operator inspection of the cached archive.

Use `pwsh -NoProfile -File .\start.ps1 -Supervise` for server restart supervision, keeping its terminal open. No Windows service or automatic startup task is installed. The direct Python command works without changing PowerShell execution policy. Application logs are under `instance/logs`; managed model logs are in the runtime directory on D:.

Set `LOCAL_AI_URL`, `LOCAL_AI_MODEL`, `LOCAL_AI_RUNTIME_DIR`, `LOCAL_AI_TIMEOUT` and `OPENBIN_WORKER_IMAGE` in the private `.env` if needed. The runtime directory defaults to `D:/SentinelRuntime/ai`; automatic runtime startup requires the default `http://127.0.0.1:11434` endpoint. Only literal loopback HTTP URLs and locally installed GGUF models are accepted. The default inference timeout is 600 seconds; the enclosing disposable process adds a bounded allowance for inspection/decompilation. Changing models requires fresh evaluation and sufficient memory.

Existing local Docker/OpenBin images must already be built. Schema 5 adds `ai_analysis`; upgrades back up the existing SQLite database. Offline restores accept schema 2, 3, 4 and 5 backups. Keep the original server secret backed up separately for existing account keys.

## What the report means

- **Suspicious observations:** at least one model observation passed literal citation validation. Interpretation still needs human review.
- **No indicators in selected evidence:** the model found none in its bounded input. This is not a whole-file safety verdict.
- **Inconclusive:** validated output did not support either triage conclusion.
- **Failed / cancelled / interrupted:** no completed verdict is available.

The adapter selects a bounded subset of functions, imports and strings and records omissions/truncation. It checks evidence IDs and exact source quotations, but cannot prove that an interpretation is correct. Packed/encrypted code, unavailable decompilation and runtime-only behavior may be missed. Untrusted binary text is supplied as evidence, never as executable tools or system instructions.

The downloaded BINNY CLI requires OpenBin authentication and an interactive terminal. This web workflow instead uses the official OpenBin Ghidra extractor and our constrained local inference adapter. Reports name that actual pipeline; they do not claim the BINNY agent ran.

## Evaluate honestly

Functional acceptance uses an inert synthetic executable and verifies the pipeline, not malware detection accuracy. For an academic/customer benchmark, obtain an authorized held-out set with independently verified benign/malicious labels. Do not derive ground truth from this model's own outputs. Export each analysis as JSON and prepare a manifest:

```json
{
  "label_source": "Describe independent analyst/dataset labeling and held-out split",
  "cases": [
    {"report": "reports/benign.json", "label": "benign"},
    {"report": "reports/malicious.json", "label": "malicious"}
  ]
}
```

```powershell
.venv\Scripts\python tools/evaluate_local_ai.py manifest.json --output evaluation.json
```

The evaluator rejects duplicate sample hashes, checks provenance, reports the confusion counts and decision coverage, and includes abstentions/failures in all-labeled denominators. It reads exports only and never opens or executes binary samples. Review false positives, false negatives, unsupported formats, runtime/memory and model digest separately. No representative labeled dataset has been supplied, so no measured detection accuracy is claimed.
