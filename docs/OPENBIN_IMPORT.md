# Local OpenBin and supervised findings

The **Local OpenBin** web page and tools/openbin_local.py wrap the official OpenBin Ghidra worker in a network-disabled Docker container. They do not invoke the uploading OpenBin CLI or any AI API. Follow [LOCAL_DEPLOYMENT.md](LOCAL_DEPLOYMENT.md) to build and verify the runtime. See [verification evidence](VERIFICATION.md) for actual execution results; downloaded binaries alone do not establish a working decompiler.

Use the same authorized sample as the Sentinel scan. Local output includes sentinel_provenance with its SHA-256, processing_location=local and ai_model_ran=false. Protect the saved code output. Raw decompilation JSON is not directly importable findings JSON.

Review code manually or with a separately configured actual model, then prepare Sentinel's own contract:

```json
{
  "schema_version": 1,
  "sha256": "<exact 64-character hash from the scan>",
  "tool": "OpenBin",
  "processing_location": "local",
  "model": "Manual review; no AI model",
  "reviewer": "<person who checked the evidence>",
  "findings": [{
    "title": "Concise observation",
    "severity": "info",
    "detail": "Explain the observation and its limits.",
    "evidence": "Function/address/line and supporting code observation."
  }]
}
```

Use an actual model identifier/configuration only when it ran. Tools: OpenBin or BINNY. Severities: info, low, medium, high. Limits: 50 findings; title 160 characters; detail/evidence 3000 each; model 200; reviewer 100; file 512 KiB.

Processing location must be local or cloud. Legacy documents without it are treated as cloud. A local decompiler followed by cloud AI is still cloud review: obtain disclosure consent before sending code and mark cloud. Local-only review needs no cloud consent. Provenance records a human declaration, not independent attestation.

On the matching scan, upload the JSON and acknowledge evidence review. Hash binding is required, importer/time are recorded, and replacements are logged. Cloud import needs recorded consent. An empty findings array does not establish safety.

Never include API keys, credentials, sample bytes, private documents or commands to execute a sample. Imported text is escaped and treated as data. This is Sentinel's contract, not a native OpenBin export or automatic AI integration.
