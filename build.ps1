<#
.SYNOPSIS
    Compiles analyzer.ps1 into a standalone Windows .exe using ps2exe.

.DESCRIPTION
    Run this once to produce ca-report-only-analyzer.exe. Requires the
    ps2exe module (installed automatically if missing) and Windows
    PowerShell 5.1 (run this with powershell.exe, not pwsh.exe, so the
    compiled exe targets the PowerShell engine present on every Windows
    machine by default).
#>

$ErrorActionPreference = "Stop"

if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Host "Installing ps2exe module..."
    Install-Module -Name ps2exe -Scope CurrentUser -Force
}
Import-Module ps2exe

$scriptPath = Join-Path $PSScriptRoot "analyzer.ps1"
$outputPath = Join-Path $PSScriptRoot "ca-report-only-analyzer.exe"
$iconPath = Join-Path $PSScriptRoot "app-icon.ico"

Write-Host "Compiling $scriptPath -> $outputPath ..."
Invoke-ps2exe `
    -inputFile $scriptPath `
    -outputFile $outputPath `
    -iconFile $iconPath `
    -title "CA Report-Only Policy Analyzer" `
    -description "Analyzes which report-only Conditional Access policies would have applied" `
    -company "" `
    -product "CA Report-Only Policy Analyzer" `
    -noConsole:$false `
    -requireAdmin:$false

Write-Host ""
Write-Host "Built: $outputPath" -ForegroundColor Green
