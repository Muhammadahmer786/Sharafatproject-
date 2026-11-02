param([switch]$IncludeOpenBin, [string]$CacheDirectory)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$pythonExe = Join-Path $projectRoot '.venv/Scripts/python.exe'
$workerArguments = @((Join-Path $PSScriptRoot 'build_workers.py'))
if ($IncludeOpenBin) { $workerArguments += '--include-openbin' }
if ($CacheDirectory) { $workerArguments += @('--cache-directory', $CacheDirectory) }
& $pythonExe @workerArguments
if ($LASTEXITCODE -ne 0) { throw 'Worker setup failed. See the error above; no native fallback was enabled.' }
