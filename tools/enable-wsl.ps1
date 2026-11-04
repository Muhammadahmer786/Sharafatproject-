# Narrow elevation: Windows features and official WSL only. Never reboots.
param([switch]$Elevated)
$ErrorActionPreference = 'Stop'
try {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        if ($Elevated) { throw 'Administrator approval was not granted.' }
        $arguments = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', ('"{0}"' -f $PSCommandPath), '-Elevated')
        $process = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList $arguments -Verb RunAs -WindowStyle Hidden -Wait -PassThru
        exit $process.ExitCode
    }
    $needsRestart = $false
    foreach ($feature in @('Microsoft-Windows-Subsystem-Linux', 'VirtualMachinePlatform')) {
        $status = Get-WindowsOptionalFeature -Online -FeatureName $feature
        if ($status.State -eq 'EnablePending') { $needsRestart = $true }
        elseif ($status.State -ne 'Enabled') {
            $result = Enable-WindowsOptionalFeature -Online -FeatureName $feature -All -NoRestart
            if ($result.RestartNeeded) { $needsRestart = $true }
        }
    }
    if ($needsRestart) { exit 3010 }
    & wsl.exe --install --no-distribution
    if ($LASTEXITCODE -eq 3010) { exit 3010 }
    if ($LASTEXITCODE -ne 0) { throw 'WSL installation failed.' }
    & wsl.exe --update
    if ($LASTEXITCODE -eq 3010) { exit 3010 }
    if ($LASTEXITCODE -ne 0) { throw 'WSL update failed.' }
    & wsl.exe --set-default-version 2
    if ($LASTEXITCODE -ne 0) { throw 'WSL 2 could not be enabled. Check firmware virtualization.' }
    exit 0
} catch {
    Write-Host ('WSL setup failed: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
