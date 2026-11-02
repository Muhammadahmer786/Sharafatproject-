param([string]$RuntimeDirectory = 'D:\SentinelRuntime\ai', [switch]$PullModel)
$ErrorActionPreference = 'Stop'
$runtimePath = Join-Path $RuntimeDirectory 'ollama-0.40.13\ollama.exe'
if (-not (Test-Path -LiteralPath $runtimePath)) { throw 'Install the local AI runtime with tools/install-local-ai.py first.' }
$env:OLLAMA_HOST = '127.0.0.1:11434'
$env:OLLAMA_MODELS = Join-Path $RuntimeDirectory 'models'
$env:OLLAMA_TMPDIR = Join-Path $RuntimeDirectory 'tmp'
$env:OLLAMA_NO_CLOUD = '1'
$env:OLLAMA_NUM_PARALLEL = '1'
$env:OLLAMA_MAX_LOADED_MODELS = '1'
$env:OLLAMA_MAX_QUEUE = '3'
$env:OLLAMA_KEEP_ALIVE = '0'
$env:OLLAMA_CONTEXT_LENGTH = '8192'
$env:CUDA_VISIBLE_DEVICES = '-1'
function Test-LocalModel {
    # Supported by both Windows PowerShell 5.1 and PowerShell 7, without proxies.
    $probe = [System.Net.HttpWebRequest]::Create('http://127.0.0.1:11434/api/version')
    $probe.Proxy = $null
    $probe.AllowAutoRedirect = $false
    $probe.Timeout = 2000
    $probe.ReadWriteTimeout = 2000
    try {
        $reply = $probe.GetResponse()
        try { return ([int]$reply.StatusCode -eq 200) }
        finally { $reply.Close() }
    } catch { return $false }
}
$modelReady = $false
$modelReady = Test-LocalModel
if (-not $modelReady) {
    $modelProcess = Start-Process -FilePath $runtimePath -ArgumentList 'serve' -WindowStyle Hidden -PassThru `
        -RedirectStandardOutput (Join-Path $RuntimeDirectory 'logs\server-out.txt') `
        -RedirectStandardError (Join-Path $RuntimeDirectory 'logs\server-error.txt')
    $modelProcess.Id | Set-Content -LiteralPath (Join-Path $RuntimeDirectory 'server.pid')
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        Start-Sleep -Seconds 1
        if (Test-LocalModel) {
            $modelReady = $true
            break
        }
        if ($modelProcess.HasExited) { throw 'Local model server stopped. Inspect its logs on D:.' }
    }
    if (-not $modelReady) { throw 'The local model server did not become ready.' }
}
if ($PullModel) {
    & $runtimePath pull qwen3:4b
    if ($LASTEXITCODE -ne 0) { throw 'The model download failed; retry the pull when connectivity is available.' }
}
Write-Output 'Local AI runtime available at http://127.0.0.1:11434 (cloud disabled for servers launched by this script).'
