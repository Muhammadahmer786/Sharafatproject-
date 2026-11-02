param([int]$Port = 5050, [switch]$Supervise)
$ErrorActionPreference = 'Stop'
$projectDir = $PSScriptRoot
$pythonExe = Join-Path $projectDir '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonExe)) {
    Write-Error 'Create the virtual environment and install requirements.txt as described in README.md.'
}
Set-Location -LiteralPath $projectDir
$failures = 0
do {
    & $pythonExe (Join-Path $projectDir 'run.py') --port $Port
    $serverExit = $LASTEXITCODE
    if (-not $Supervise -or $serverExit -eq 0) { break }
    $failures++
    if ($failures -ge 5) { throw 'Server stopped five times. Run run.py doctor and inspect instance/logs.' }
    Write-Warning 'Local server stopped unexpectedly; restarting in five seconds.'
    Start-Sleep -Seconds 5
} while ($Supervise)
