<#
.SYNOPSIS
  Run the Stage 2 crash report inside the AFL++ container.

.EXAMPLE
  .\scripts\report.ps1
  .\scripts\report.ps1 -OutDirs out_bad,out_good
  .\scripts\report.ps1 -Format markdown -Output docs/stage2-campaign-results.md
#>
[CmdletBinding()]
param(
  [Parameter(Position = 0)]
  [string[]] $OutDirs = @(),

  [ValidateSet("text", "markdown")]
  [string] $Format = "text",

  [string] $Output = "",

  [string] $Image = "aflplusplus/aflplusplus"
)

$ProjectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path

$dockerArgs = @(
  "run", "--rm", "-i",
  "-v", "${ProjectRoot}:/src",
  "-w", "/src",
  $Image,
  "python3", "scripts/report.py",
  "--format", $Format
)
if ($Output) {
  $dockerArgs += @("--output", $Output)
}
if ($OutDirs.Count -gt 0) {
  $dockerArgs += $OutDirs
}

& docker @dockerArgs
exit $LASTEXITCODE
