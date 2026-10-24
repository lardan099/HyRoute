# Builds bin\HyRoute.exe (GUI), bin\hyroute-updater.exe,
# bin\hyroutectl.exe (command line) and bin\hyroute-server.exe (HyRoute
# Server, opened from the servers page) next to hysteria.exe and WinDivert.
# Needs only Go: frontend\dist and web\admin\dist are committed.
#   .\scripts\build.ps1            build
#   .\scripts\build.ps1 -Frontend  also rebuild both UIs (needs Node.js/npm)
#Requires -Version 5.1
param([switch]$Frontend)
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
foreach ($p in 'HyRoute', 'hyroute-updater', 'hyroutectl', 'hyroute-server') {
    if (Get-Process $p -ErrorAction SilentlyContinue) {
        throw "$p.exe is running: close it first, otherwise the exe cannot be replaced"
    }
}
$deps = Get-Content (Join-Path $root 'build\deps.json') -Raw | ConvertFrom-Json
& (Join-Path $PSScriptRoot 'fetch-deps.ps1')
Push-Location $root
try {
    foreach ($ui in 'frontend', 'web\admin') {
        if ($Frontend -or -not (Test-Path "$ui\dist\index.html")) {
            Push-Location $ui
            try {
                npm ci
                if ($LASTEXITCODE -ne 0) { throw "npm ci failed ($ui)" }
                npm run build
                if ($LASTEXITCODE -ne 0) { throw "UI build failed ($ui)" }
            } finally { Pop-Location }
        }
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
        go run "github.com/tc-hib/go-winres@$($deps.tools.goWinres)" make --arch amd64 --in winres.json --out ..\..\cmd\hyroute\rsrc --file-version "$num.0" --product-version "$num.0"
        if ($LASTEXITCODE -ne 0) { throw 'go-winres failed' }
        # hyroutectl: asInvoker, a console program.
        go run "github.com/tc-hib/go-winres@$($deps.tools.goWinres)" make --arch amd64 --in hyroutectl.json --out ..\..\cmd\hyroutectl\rsrc --file-version "$num.0" --product-version "$num.0"
        if ($LASTEXITCODE -ne 0) { throw 'go-winres (hyroutectl) failed' }
    } finally { Pop-Location }
    # HyRoute Server first: HyRoute.exe pins its SHA-256 and starts only
    # that file (cmd/hyroute/serverpanel.go). A console program (its window
    # is the panel's).
    go build -trimpath -ldflags "-s -w -X main.version=$ver" -o bin\hyroute-server.exe .\cmd\hyroute-server
    if ($LASTEXITCODE -ne 0) { throw 'go build (hyroute-server) failed' }
    $panel = (Get-FileHash -Algorithm SHA256 bin\hyroute-server.exe).Hash.ToLowerInvariant()
    go build -tags desktop,production -trimpath -ldflags "-H windowsgui $ld -X main.panelSHA256=$panel" -o bin\HyRoute.exe .\cmd\hyroute
    if ($LASTEXITCODE -ne 0) { throw 'go build (HyRoute) failed' }
    go build -trimpath -ldflags "-H windowsgui" -o bin\hyroute-updater.exe .\cmd\hyroute-updater
    if ($LASTEXITCODE -ne 0) { throw 'go build (updater) failed' }
    # Console subsystem: no -H windowsgui.
    go build -trimpath -ldflags "$ld" -o bin\hyroutectl.exe .\cmd\hyroutectl
    if ($LASTEXITCODE -ne 0) { throw 'go build (hyroutectl) failed' }
    Write-Host "Built bin\HyRoute.exe, bin\hyroute-updater.exe, bin\hyroutectl.exe and bin\hyroute-server.exe ($ver, $rev)"
} finally { Pop-Location }
