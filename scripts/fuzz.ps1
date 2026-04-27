<#
.SYNOPSIS
  One-line Windows wrapper to launch an AFL++ campaign in Docker.

.EXAMPLE
  .\scripts\fuzz.ps1 stage2_afl_bad_validator
  .\scripts\fuzz.ps1 stage2_afl_good_validator out_good 900
  .\scripts\fuzz.ps1 stage2_afl_length_only_indexed out_indexed 1800

.DESCRIPTION
  Mounts the project root at /src inside the aflplusplus/aflplusplus
  container and delegates to scripts/run_afl.sh. Output artifacts
  (queue/, crashes/, fuzzer_stats) land in <OutDir>/ on the host.

  Press Ctrl-C to end the campaign early; afl-fuzz will write its
  final stats before exiting.
#>
param(
  [Parameter(Mandatory = $true, Position = 0)]
  [string] $Target,

  [Parameter(Position = 1)]
  [string] $OutDir = "",

  [Parameter(Position = 2)]
  [int] $BudgetSeconds = 600,

  [string] $Image = "aflplusplus/aflplusplus"
)

if ([string]::IsNullOrEmpty($OutDir)) {
  # Default output dir mirrors the target name.
  $OutDir = $Target -replace "^stage2_afl_", "out_"
}

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

Write-Host "[fuzz] project root : $ProjectRoot"
Write-Host "[fuzz] target       : $Target"
Write-Host "[fuzz] output dir   : $OutDir"
Write-Host "[fuzz] budget (sec) : $BudgetSeconds"
Write-Host "[fuzz] image        : $Image"
Write-Host ""

docker run --rm -it `
  -v "${ProjectRoot}:/src" `
  -w /src `
  $Image `
  bash scripts/run_afl.sh $Target $OutDir $BudgetSeconds

if ($LASTEXITCODE -ne 0) {
  Write-Host "[fuzz] container exited with code $LASTEXITCODE" -ForegroundColor Yellow
  exit $LASTEXITCODE
}
