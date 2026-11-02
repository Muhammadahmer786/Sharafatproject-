$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$instanceRoot = Join-Path $projectRoot 'instance'
New-Item -ItemType Directory -Force -Path $instanceRoot | Out-Null
$accountSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$privateTargets = @($instanceRoot)
$envPath = Join-Path $projectRoot '.env'
if (Test-Path -LiteralPath $envPath) { $privateTargets += $envPath }
foreach ($privateTarget in $privateTargets) {
    # These are application-owned paths. Keep only this operator, SYSTEM and Administrators.
    $isDirectory = (Get-Item -LiteralPath $privateTarget).PSIsContainer
    $inheritFlags = if ($isDirectory) { '(OI)(CI)' } else { '' }
    & icacls.exe $privateTarget /inheritance:r /grant:r "*${accountSid}:${inheritFlags}F" "*S-1-5-18:${inheritFlags}F" "*S-1-5-32-544:${inheritFlags}F" /Q
    if ($LASTEXITCODE -ne 0) { throw 'Could not restrict local application files.' }
}
Write-Host 'Local state and environment access is restricted to this Windows operator and system administrators.'
