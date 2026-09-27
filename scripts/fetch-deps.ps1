# Downloads hysteria.exe and WinDivert into bin\ and verifies SHA256.
# Versions and hashes are pinned in deps.json (single source of truth).
# The Hysteria hash is additionally cross-checked against the release's
# official hashes.txt.
#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$root = Split-Path -Parent $PSScriptRoot
$deps = Get-Content (Join-Path $root 'deps.json') -Raw | ConvertFrom-Json
$bin = Join-Path $root 'bin'
New-Item -ItemType Directory -Force $bin | Out-Null
$tmp = Join-Path ([IO.Path]::GetTempPath()) ("hyroute-deps-" + [guid]::NewGuid())
New-Item -ItemType Directory -Force $tmp | Out-Null

function Get-Sha256([string]$path) { (Get-FileHash -Algorithm SHA256 $path).Hash.ToLowerInvariant() }

function Assert-Hash([string]$path, [string]$want, [string]$what) {
    $got = Get-Sha256 $path
    if ($got -ne $want.ToLowerInvariant()) {
        throw "$what : SHA256 mismatch`n  expected $want`n  got      $got"
    }
    Write-Host "  ok  $what  $got"
}

try {
    # --- Hysteria ---
    $h = $deps.hysteria
    $dest = Join-Path $bin $h.dest
    if ((Test-Path $dest) -and ((Get-Sha256 $dest) -eq $h.sha256)) {
        Write-Host "hysteria $($h.version): already present"
    } else {
        Write-Host "hysteria $($h.version): downloading"
        $hashes = Join-Path $tmp 'hashes.txt'
        Invoke-WebRequest -UseBasicParsing $h.hashesUrl -OutFile $hashes
        $line = Get-Content $hashes | Where-Object { $_ -match ('\s' + [regex]::Escape($h.hashesName) + '$') }
        if (-not $line) { throw "hashes.txt has no entry for $($h.hashesName)" }
        $official = ($line -split '\s+')[0].ToLowerInvariant()
        if ($official -ne $h.sha256) {
            throw "deps.json hash for hysteria differs from the release hashes.txt ($official)"
        }
        $f = Join-Path $tmp $h.dest
        Invoke-WebRequest -UseBasicParsing $h.url -OutFile $f
        Assert-Hash $f $h.sha256 'hysteria.exe'
        Copy-Item $f $dest -Force
    }

    # --- WinDivert ---
    $w = $deps.windivert
    $need = $false
    foreach ($p in $w.files.PSObject.Properties) {
        $d = Join-Path $bin (Split-Path $p.Name -Leaf)
        if (-not (Test-Path $d) -or ((Get-Sha256 $d) -ne $p.Value)) { $need = $true }
    }
    if (-not $need) {
        Write-Host "WinDivert $($w.version): already present"
    } else {
        Write-Host "WinDivert $($w.version): downloading"
        $zip = Join-Path $tmp 'windivert.zip'
        Invoke-WebRequest -UseBasicParsing $w.url -OutFile $zip
        Assert-Hash $zip $w.sha256 'WinDivert zip'
        Add-Type -AssemblyName System.IO.Compression.FileSystem
        $archive = [IO.Compression.ZipFile]::OpenRead($zip)
        try {
            foreach ($p in $w.files.PSObject.Properties) {
                $entry = $archive.GetEntry($p.Name)
                if (-not $entry) { throw "zip has no $($p.Name)" }
                $out = Join-Path $tmp (Split-Path $p.Name -Leaf)
                [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $out, $true)
                Assert-Hash $out $p.Value (Split-Path $p.Name -Leaf)
                Copy-Item $out (Join-Path $bin (Split-Path $p.Name -Leaf)) -Force
            }
        } finally { $archive.Dispose() }
    }
    Write-Host "Dependencies are in $bin"
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
