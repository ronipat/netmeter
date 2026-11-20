param(
    [switch]$Offline
)
$ErrorActionPreference = "Stop"
Push-Location $PSScriptRoot
try {
    $offlineArg = if ($Offline) { "--offline" } else { "" }
    Write-Host "[1/3] Building release netmeter.exe and netmeter-cli.exe..."
    if ($Offline) {
        cargo build --release --offline --bin netmeter --bin netmeter-cli
    } else {
        cargo build --release --bin netmeter --bin netmeter-cli
    }
    if ($LASTEXITCODE -ne 0) { throw "Payload build failed" }

    Write-Host "[2/3] Building self-contained NetMeter-Setup.exe (embed-payload)..."
    if ($Offline) {
        cargo build --release --offline --bin netmeter-setup --features embed-payload
    } else {
        cargo build --release --bin netmeter-setup --features embed-payload
    }
    if ($LASTEXITCODE -ne 0) { throw "Setup build failed" }

    Write-Host "[3/3] Packaging netmeter/dist/NetMeter-Setup.exe..."
    New-Item -ItemType Directory -Force -Path "dist" | Out-Null
    Copy-Item "target\release\netmeter-setup.exe" "dist\NetMeter-Setup.exe" -Force
    $sizeMB = [math]::Round((Get-Item "dist\NetMeter-Setup.exe").Length / 1MB, 2)
    Write-Host "Ready: dist\NetMeter-Setup.exe ($sizeMB MB)"
} finally {
    Pop-Location
}
