# Installs pinned Syft, Grype, OSV-Scanner into tools/bin (D2-01). Verifies SHA-256 against release checksums.
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
. (Join-Path $PSScriptRoot 'tool_versions.ps1')
$bin = Join-Path $root 'tools\bin'
$dl = Join-Path $root 'tools\download'
New-Item -ItemType Directory -Force $bin, $dl | Out-Null

function Get-Verified($url, $out, $sumsUrl, $name) {
    if (-not (Test-Path $out)) { Invoke-WebRequest $url -OutFile $out -UseBasicParsing }
    $content = (Invoke-WebRequest $sumsUrl -UseBasicParsing).Content
    if ($content -is [byte[]]) { $content = [Text.Encoding]::UTF8.GetString($content) }
    $sums = $content -split "`r?`n"
    $line = $sums | Where-Object { $_ -match [regex]::Escape($name) + '\s*$' } | Select-Object -First 1
    if (-not $line) { throw "no checksum for $name" }
    $want = ($line -split '\s+')[0].ToLower()
    $got = (Get-FileHash $out -Algorithm SHA256).Hash.ToLower()
    if ($want -ne $got) { Remove-Item $out; throw "checksum mismatch for $name" }
    Write-Host "verified $name"
}

foreach ($t in @(@{repo='anchore/syft'; v=$SYFT_VERSION; n='syft'}, @{repo='anchore/grype'; v=$GRYPE_VERSION; n='grype'})) {
    $name = "$($t.n)_$($t.v)_windows_amd64.zip"
    $base = "https://github.com/$($t.repo)/releases/download/v$($t.v)"
    $zip = Join-Path $dl $name
    Get-Verified "$base/$name" $zip "$base/$($t.n)_$($t.v)_checksums.txt" $name
    Expand-Archive $zip -DestinationPath (Join-Path $dl $t.n) -Force
    Copy-Item (Join-Path $dl "$($t.n)\$($t.n).exe") $bin -Force
}

$osvName = 'osv-scanner_windows_amd64.exe'
$osvBase = "https://github.com/google/osv-scanner/releases/download/v$OSV_VERSION"
$osvOut = Join-Path $dl $osvName
Get-Verified "$osvBase/$osvName" $osvOut "$osvBase/osv-scanner_SHA256SUMS" $osvName
Copy-Item $osvOut (Join-Path $bin 'osv-scanner.exe') -Force

& (Join-Path $bin 'syft.exe') version | Select-String '^Version'
& (Join-Path $bin 'grype.exe') version | Select-String '^Version'
& (Join-Path $bin 'osv-scanner.exe') --version | Select-Object -First 1
Write-Host 'Updating Grype DB...'
& (Join-Path $bin 'grype.exe') db update
