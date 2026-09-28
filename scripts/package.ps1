# Packs a release: dist\HyRoute-<ver>-windows-amd64.zip (flat: HyRoute.exe,
# hyroute-updater.exe, hyroutectl.exe, hysteria.exe, WinDivert.dll, WinDivert64.sys,
# manifest.json with every file's SHA256, LICENSE.txt, THIRD-PARTY-NOTICES.txt)
# and dist\SHA256SUMS.
# Run after scripts\build.ps1 on a v* tag.
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Push-Location $root
try {
    # The release workflow names the tag it packs in HYROUTE_VERSION (as
    # for build.ps1): with two tags on one commit, git describe may pick
    # the other one.
    $ver = $env:HYROUTE_VERSION
    if ($ver) {
        if ((git rev-parse -q --verify "refs/tags/$ver^{commit}" 2>$null) -ne (git rev-parse HEAD)) {
            throw "HEAD is not tag $ver (HYROUTE_VERSION)"
        }
    } else {
        $ver = (git describe --tags --exact-match --match 'v[0-9]*' 2>$null)
    }
    if (-not $ver) { throw 'HEAD is not a v* tag: tag the release first (git tag v0.5.0)' }
    # frontend/dist is rebuilt from the sources by build.ps1 -Frontend in
    # the release workflow; any other change means the tag is not what
    # gets packed.
    if (git status --porcelain -- . ':!frontend/dist' 2>$null) { throw 'working tree is dirty' }
    $name = "HyRoute-$($ver.TrimStart('v'))-windows-amd64"
    $dist = Join-Path $root 'dist'
    $stage = Join-Path $dist $name
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
    New-Item -ItemType Directory -Force $stage | Out-Null
    $files = 'HyRoute.exe', 'hyroute-updater.exe', 'hyroutectl.exe', 'hysteria.exe', 'WinDivert.dll', 'WinDivert64.sys'
    $manifest = [ordered]@{ version = $ver; files = [ordered]@{} }
    foreach ($f in $files) {
        $src = Join-Path 'bin' $f
        if (-not (Test-Path $src)) { throw "missing bin\$f (run scripts\build.ps1)" }
        Copy-Item $src $stage
        $manifest.files[$f] = (Get-FileHash -Algorithm SHA256 $src).Hash.ToLowerInvariant()
    }
    [IO.File]::WriteAllText((Join-Path $stage 'manifest.json'), ($manifest | ConvertTo-Json), (New-Object Text.UTF8Encoding $false))
    # Licenses travel with the binaries; the updater ignores files outside
    # the manifest.
    Copy-Item LICENSE (Join-Path $stage 'LICENSE.txt')
    Copy-Item THIRD-PARTY-NOTICES.txt $stage
    $zip = Join-Path $dist "$name.zip"
    Remove-Item $zip -ErrorAction SilentlyContinue
    Compress-Archive -Path (Join-Path $stage '*') -DestinationPath $zip
    $sum = (Get-FileHash -Algorithm SHA256 $zip).Hash.ToLowerInvariant()
    [IO.File]::WriteAllText((Join-Path $dist 'SHA256SUMS'), "$sum  $name.zip`n", (New-Object Text.UTF8Encoding $false))
    Write-Host "Packed $zip ($sum)"
} finally { Pop-Location }
