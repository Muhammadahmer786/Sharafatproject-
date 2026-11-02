$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$vendorRoot = Join-Path $projectRoot 'vendor'
New-Item -ItemType Directory -Force -Path $vendorRoot | Out-Null
$downloads = @(
    @{ Name='openbin'; Url='https://github.com/openbin-ai/platform/releases/download/openbin-v0.10.0/openbin-windows-amd64.zip'; Sha='B08B0A73372D4F83E337D88BA33E57FDCFAC57A7490F72CE7E5BC5897D6976E7' },
    @{ Name='binny'; Url='https://github.com/openbin-ai/binny-releases/releases/download/v0.1.0-beta.3/binny-windows-amd64.zip'; Sha='D8BFFFB1E97311C87723E03259BA07E3AF0E2DA5366D2133903FF6525107E70E' }
)
foreach ($download in $downloads) {
    $archivePath = Join-Path $vendorRoot ($download.Name + '-windows-amd64.zip')
    if (-not (Test-Path -LiteralPath $archivePath)) {
        Invoke-WebRequest -Uri $download.Url -OutFile $archivePath
    }
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $download.Sha) {
        throw 'Archive differs from the reviewed download. Do not execute it until the release has been checked.'
    }
    Expand-Archive -LiteralPath $archivePath -DestinationPath (Join-Path $vendorRoot $download.Name) -Force
}
Write-Host 'Official tools installed inside vendor. No PATH or cloud-account settings were changed.'
Write-Host 'Use tools/openbin_local.py for local-only decompilation. The upstream openbin decompile command uploads code.'
