<#
Installs runet-direct on Windows from the latest GitHub release.

  Open PowerShell AS ADMINISTRATOR, then:
    irm https://raw.githubusercontent.com/iResultMan/runet-direct/main/install.ps1 | iex
  or, to pin a version / skip starting:
    .\install.ps1 -Version v1.0.0 -NoStart

It downloads one executable, checks its SHA-256 and runs `runet-direct.exe install`, which registers
a scheduled task that starts at boot as SYSTEM and starts it now. Read it before running it.
#>
param([string]$Version = "", [switch]$NoStart)
$ErrorActionPreference = 'Stop'

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
  throw "Run this in an elevated PowerShell (Run as administrator)."
}

$repo = 'iResultMan/runet-direct'
$asset = 'runet-direct-x86_64-pc-windows-msvc.zip'
$base = if ($Version) { "https://github.com/$repo/releases/download/$Version" } else { "https://github.com/$repo/releases/latest/download" }

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("runet-direct-" + [Guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
  Write-Host "downloading $asset ..."
  Invoke-WebRequest "$base/$asset" -OutFile "$tmp\$asset" -UseBasicParsing
  Invoke-WebRequest "$base/$asset.sha256" -OutFile "$tmp\$asset.sha256" -UseBasicParsing

  $want = ((Get-Content "$tmp\$asset.sha256" -Raw).Trim() -split '\s+')[0].ToLower()
  $got = (Get-FileHash "$tmp\$asset" -Algorithm SHA256).Hash.ToLower()
  if ($want -ne $got) { throw "checksum mismatch: expected $want, got $got" }

  Expand-Archive "$tmp\$asset" -DestinationPath $tmp -Force
  $args = @('install'); if ($NoStart) { $args += '--no-start' }
  & "$tmp\runet-direct.exe" @args
  if ($LASTEXITCODE -ne 0) { throw "runet-direct install failed (exit $LASTEXITCODE)" }
} finally {
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
}
