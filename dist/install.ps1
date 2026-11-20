param(
    [string]$InstallDir = "$env:ProgramFiles\NetMeter",
    [switch]$NoAutostart,
    [switch]$NoLaunch
)
$ErrorActionPreference = "Stop"

$setupExe = Join-Path $PSScriptRoot "NetMeter-Setup.exe"
if (-not (Test-Path $setupExe)) {
    throw "NetMeter-Setup.exe not found in $PSScriptRoot. Run ..\build-installer.ps1 first."
}

$argList = @("--silent", "--dir", "`"$InstallDir`"")
if ($NoAutostart) { $argList += "--no-autostart" }
if ($NoLaunch) { $argList += "--no-launch" }

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    $proc = Start-Process -FilePath $setupExe -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden
    exit $proc.ExitCode
} else {
    Write-Host "Requesting Administrator permission to install Net Meter into $InstallDir..."
    $proc = Start-Process -FilePath $setupExe -ArgumentList $argList -Verb RunAs -Wait -PassThru
    exit $proc.ExitCode
}
