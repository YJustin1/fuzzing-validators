<#
.SYNOPSIS
  Batch runner: fuzz every Stage 2 AFL++ target sequentially in Docker.

.EXAMPLE
  .\scripts\fuzz_all.ps1                 # 300s per target, default image
  .\scripts\fuzz_all.ps1 -BudgetSeconds 600
  .\scripts\fuzz_all.ps1 -BudgetSeconds 60 -Image aflplusplus/aflplusplus

.DESCRIPTION
  Delegates to scripts/fuzz_all.sh inside the aflplusplus/aflplusplus
  container. Unlike fuzz.ps1 this runs non-interactively (no TTY) so it
  can be dispatched from scripts/CI and has AFL_NO_UI=1 set so afl-fuzz
  emits plain text logs instead of its curses UI.

  Outputs:
    out_<target_suffix>/           # per-campaign AFL output dirs
    results/logs/<target>.log      # per-campaign raw afl-fuzz log
#>
param(
  [int]    $BudgetSeconds = 300,
  [string] $Image         = "aflplusplus/aflplusplus"
)

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Write-Host "[fuzz-all] project root : $ProjectRoot"
Write-Host "[fuzz-all] image        : $Image"
Write-Host "[fuzz-all] per-target   : $BudgetSeconds seconds"
Write-Host ""

docker run --rm -i `
  -v "${ProjectRoot}:/src" `
  -w /src `
  $Image `
  bash scripts/fuzz_all.sh $BudgetSeconds

if ($LASTEXITCODE -ne 0) {
  Write-Host "[fuzz-all] container exited with code $LASTEXITCODE" -ForegroundColor Yellow
  exit $LASTEXITCODE
}

Write-Host ""
Write-Host "[fuzz-all] campaigns complete. Generate reports with:"
Write-Host "    .\scripts\report.ps1"
