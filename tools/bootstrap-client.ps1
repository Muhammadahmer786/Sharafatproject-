# Runs in built-in Windows PowerShell 5.1. Only Python bootstrap happens here.
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $projectRoot

function Find-SentinelPython {
    $localPython = Join-Path $projectRoot '.venv\Scripts\python.exe'
    $candidates = @($localPython, (Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\pymanager.exe'))
    foreach ($name in @('py.exe', 'python.exe', 'pymanager.exe')) {
        $command = Get-Command $name -ErrorAction SilentlyContinue
        if ($command) { $candidates += $command.Source }
    }
    foreach ($candidate in $candidates) {
        if (-not (Test-Path -LiteralPath $candidate)) { continue }
        $arguments = @()
        $leaf = Split-Path -Leaf $candidate
        if ($leaf -eq 'python.exe' -and $candidate -like '*\Microsoft\WindowsApps\*') { continue }
        if ($leaf -eq 'py.exe') { $arguments = @('-3.12') }
        if ($leaf -eq 'pymanager.exe') { $arguments = @('exec', '-V:3.12') }
        $arguments += @('-c', 'import sys; print(sys.executable) if sys.version_info[:2] == (3,12) and sys.maxsize > 2**32 else sys.exit(1)')
        try {
            $output = & $candidate @arguments 2>$null
            if ($LASTEXITCODE -eq 0 -and $output) {
                $path = ([string]($output | Select-Object -Last 1)).Trim()
                if (Test-Path -LiteralPath $path) { return $path }
            }
        } catch { }
    }
    return $null
}

try {
    if (-not [Environment]::Is64BitOperatingSystem -or $env:PROCESSOR_ARCHITECTURE -eq 'ARM64') {
        throw 'This package requires Windows on an Intel/AMD 64-bit PC.'
    }
    Write-Host 'This launcher downloads missing local dependencies and model weights.'
    Write-Host 'Windows may request administrator approval or a reboot. Passwords and the optional API key stay private.'
    $python = Find-SentinelPython
    if (-not $python) {
        $manager = Get-Command pymanager.exe -ErrorAction SilentlyContinue
        if (-not $manager) {
            $winget = Get-Command winget.exe -ErrorAction SilentlyContinue
            if (-not $winget) {
                throw 'Windows App Installer (winget) is missing. Install/update App Installer from Microsoft Store, then run this file again. Alternatively install Python 3.12 from python.org.'
            }
            Write-Host 'Installing the official Python install manager from Microsoft Store; review any package agreement prompt.'
            & $winget.Source install --id 9NQ7512CXL7T --exact --source msstore --accept-source-agreements
            if ($LASTEXITCODE -ne 0) { throw 'Python manager installation did not finish. Resolve the Windows/Store message and rerun.' }
            $manager = Get-Command pymanager.exe -ErrorAction SilentlyContinue
            if (-not $manager) {
                $managerPath = Join-Path $env:LOCALAPPDATA 'Microsoft\WindowsApps\pymanager.exe'
                if (Test-Path -LiteralPath $managerPath) { $manager = @{Source=$managerPath} }
            }
        }
        if (-not $manager) { throw 'Open a new terminal or restart Windows to activate Python manager, then run this file again.' }
        & $manager.Source install 3.12
        if ($LASTEXITCODE -ne 0) { throw 'Python 3.12 download failed. Rerun this launcher when the connection is available.' }
        $python = Find-SentinelPython
        if (-not $python) { throw 'Python 3.12 is installed but not discoverable. Open a new terminal and rerun this file.' }
    }
    & $python (Join-Path $projectRoot 'setup_client.py')
    exit $LASTEXITCODE
} catch {
    Write-Host ('SETUP STOPPED: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
