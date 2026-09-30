$ErrorActionPreference = 'Stop'

$Root = Split-Path -Parent $PSScriptRoot
$Target = 'x86_64-pc-windows-msvc'

Push-Location $PSScriptRoot
try {
    rustup target add $Target | Out-Host
    cargo build --release --target $Target
} finally {
    Pop-Location
}

$OutDir = Join-Path $Root 'dist\rust-engine'
$BuiltExe = Join-Path $PSScriptRoot "target\$Target\release\orbis-engine.exe"
$OutExe = Join-Path $OutDir 'orbis-engine.exe'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Copy-Item $BuiltExe $OutExe -Force

Write-Host "Built: $OutExe"
