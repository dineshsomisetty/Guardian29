# D5-01: clone the demo targets into targets/ at pinned commits (idempotent).
#   powershell -ExecutionPolicy Bypass -File scripts/fetch_targets.ps1
# Re-running skips the clone when the folder exists and only makes sure the pinned commit is checked out.
# targets/ is gitignored. Never run the targets' install scripts outside the sandbox (plan §0.6).
$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
$targets = Join-Path $root 'targets'
New-Item -ItemType Directory -Force $targets | Out-Null

$pins = @(
    @{ name = 'juice-shop'; url = 'https://github.com/juice-shop/juice-shop.git';    commit = 'c9f99228d' },
    @{ name = 'pygoat';     url = 'https://github.com/adeyosemanputra/pygoat.git'; commit = '2aa4cc1' }
)

function Invoke-Git {
    & git @args
    if ($LASTEXITCODE -ne 0) { throw "git $($args -join ' ') failed ($LASTEXITCODE)" }
}

foreach ($t in $pins) {
    $dir = Join-Path $targets $t.name
    if (Test-Path (Join-Path $dir '.git')) {
        Write-Host "$($t.name): present, skipping clone"
    } else {
        Write-Host "$($t.name): cloning $($t.url)"
        Invoke-Git clone --no-checkout $t.url $dir
    }
    # make sure the pinned commit is available locally (short SHA -> fetch full history if needed)
    & git -C $dir cat-file -e "$($t.commit)^{commit}" 2>$null
    if ($LASTEXITCODE -ne 0) { Invoke-Git -C $dir fetch --quiet origin }
    $want = (& git -C $dir rev-parse "$($t.commit)^{commit}").Trim()
    $have = (& git -C $dir rev-parse HEAD 2>$null)
    if ($have) { $have = $have.Trim() }
    if ($have -eq $want) {
        Write-Host "$($t.name): at $($want.Substring(0, 12)) (ok)"
        if (& git -C $dir status --porcelain) { Write-Warning "$($t.name): working tree has local changes" }
    } else {
        Invoke-Git -C $dir -c advice.detachedHead=false checkout --quiet $want
        Write-Host "$($t.name): checked out $($want.Substring(0, 12))"
    }
}
