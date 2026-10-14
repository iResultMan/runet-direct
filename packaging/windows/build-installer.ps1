# Build the Windows installer around an already built runet-direct.exe (needs Inno Setup 6: choco install innosetup).
#   .\packaging\windows\build-installer.ps1 -Exe target\release\runet-direct.exe -Version 0.1.0 -Out dist\runet-direct-setup-x86_64.exe
param(
  [Parameter(Mandatory)] [string]$Exe,
  [Parameter(Mandatory)] [string]$Version,
  [Parameter(Mandatory)] [string]$Out
)
$ErrorActionPreference = 'Stop'
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$iscc = @("$env:ProgramFiles(x86)\Inno Setup 6\ISCC.exe", "$env:ProgramFiles\Inno Setup 6\ISCC.exe") | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $iscc) { throw "Inno Setup 6 not found (choco install innosetup -y)" }
$exeFull = (Resolve-Path $Exe).Path
& $iscc "/DAppVersion=$Version" "/DSourceExe=$exeFull" "/O$here" "$here\runet-direct.iss"
if ($LASTEXITCODE -ne 0) { throw "ISCC failed ($LASTEXITCODE)" }
New-Item -ItemType Directory -Force -Path (Split-Path -Parent $Out) | Out-Null
Move-Item -Force "$here\runet-direct-setup-x86_64.exe" $Out
Write-Host "built $Out"
