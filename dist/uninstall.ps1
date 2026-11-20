param(
    [string]$InstallDir = ""
)
$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($InstallDir)) {
    $regPath = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\NetMeter"
    if (Test-Path $regPath) {
        $loc = (Get-ItemProperty -Path $regPath -Name "InstallLocation" -ErrorAction SilentlyContinue).InstallLocation
        if (-not [string]::IsNullOrWhiteSpace($loc)) {
            $InstallDir = $loc
        }
    }
    if ([string]::IsNullOrWhiteSpace($InstallDir)) {
        $InstallDir = Join-Path $env:ProgramFiles "NetMeter"
    }
}

$setupExe = Join-Path $PSScriptRoot "NetMeter-Setup.exe"
$installedUninst = Join-Path $InstallDir "uninstall.exe"

$exeToRun = if (Test-Path $setupExe) {
    $setupExe
} elseif (Test-Path $installedUninst) {
    $installedUninst
} else {
    Write-Host "Net Meter is not installed and NetMeter-Setup.exe was not found."
    exit 0
}

# Copy installed uninstaller to %TEMP% if we are running directly from inside $InstallDir
if ($exeToRun -eq $installedUninst) {
    $tempUninst = Join-Path $env:TEMP "netmeter-uninstall.exe"
    Copy-Item -Path $installedUninst -Destination $tempUninst -Force
    $exeToRun = $tempUninst
}

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

$argList = @("--silent", "--uninstall", "--dir", "`"$InstallDir`"")

if ($isAdmin) {
    $proc = Start-Process -FilePath $exeToRun -ArgumentList $argList -Wait -PassThru -WindowStyle Hidden
    exit $proc.ExitCode
} else {
    Write-Host "Requesting Administrator permission to stop Net Meter and uninstall from $InstallDir..."
    $proc = Start-Process -FilePath $exeToRun -ArgumentList $argList -Verb RunAs -Wait -PassThru
    exit $proc.ExitCode
}
