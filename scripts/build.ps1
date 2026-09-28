# Builds bin\HyRoute.exe (GUI) and bin\hyroute-updater.exe next to
# hysteria.exe and WinDivert.
# Needs only Go: frontend\dist is committed.
#   .\scripts\build.ps1            build
#   .\scripts\build.ps1 -Frontend  also rebuild the UI (needs Node.js/npm)
#Requires -Version 5.1
param([switch]$Frontend)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
foreach ($p in 'HyRoute', 'hyroute-updater') {
    if (Get-Process $p -ErrorAction SilentlyContinue) {
        throw "$p.exe is running: close it first, otherwise the exe cannot be replaced"
    }
}
$deps = Get-Content (Join-Path $root 'deps.json') -Raw | ConvertFrom-Json
& (Join-Path $PSScriptRoot 'fetch-deps.ps1')
Push-Location $root
try {
    if ($Frontend -or -not (Test-Path 'frontend\dist\index.html')) {
        Push-Location frontend
        try {
            npm ci
            if ($LASTEXITCODE -ne 0) { throw 'npm ci failed' }
            npm run build
            if ($LASTEXITCODE -ne 0) { throw 'frontend build failed' }
        } finally { Pop-Location }
    }
    $env:GOOS = 'windows'; $env:GOARCH = 'amd64'; $env:CGO_ENABLED = '0'
    go vet ./...
    if ($LASTEXITCODE -ne 0) { throw 'go vet failed' }
    $rev = (git rev-parse --short HEAD 2>$null)
    if (-not $rev) { $rev = 'unknown' }
    if (git status --porcelain 2>$null) { $rev += '-dirty' }
    # Release version from the nearest v* tag; untagged builds are dev
    # builds (no automatic update checks). The release workflow names the
    # tag it builds in HYROUTE_VERSION: with two tags on one commit, git
    # describe may pick the other one.
    $ver = $env:HYROUTE_VERSION
    if ($ver) {
        if ((git rev-parse -q --verify "refs/tags/$ver^{commit}" 2>$null) -ne (git rev-parse HEAD)) {
            throw "HEAD is not tag $ver (HYROUTE_VERSION)"
        }
    } else {
        $ver = (git describe --tags --match 'v[0-9]*' 2>$null)
    }
    if (-not $ver) { $ver = 'v0.0.0-dev' }
    $ld = "-X main.build=$rev -X main.version=$ver"

    # Manifest (requireAdministrator), icon and version info.
    Push-Location build\windows
    try {
        # File properties show the release version (1.2.3 of v1.2.3-beta.1).
        $num = ($ver -replace '^v', '') -replace '[-+].*$', ''
        if ($num -notmatch '^\d+\.\d+\.\d+$') { $num = '0.0.0' }
        go run "github.com/tc-hib/go-winres@$($deps.tools.goWinres)" make --arch amd64 --in winres.json --out ..\..\rsrc --file-version "$num.0" --product-version "$num.0"
        if ($LASTEXITCODE -ne 0) { throw 'go-winres failed' }
    } finally { Pop-Location }
    go build -tags desktop,production -trimpath -ldflags "-H windowsgui $ld" -o bin\HyRoute.exe .
    if ($LASTEXITCODE -ne 0) { throw 'go build (HyRoute) failed' }
    go build -trimpath -ldflags "-H windowsgui" -o bin\hyroute-updater.exe .\cmd\hyroute-updater
    if ($LASTEXITCODE -ne 0) { throw 'go build (updater) failed' }
    Write-Host "Built bin\HyRoute.exe and bin\hyroute-updater.exe ($ver, $rev)"
} finally { Pop-Location }
