# Tests the "run another analysis" loop added to Invoke-CaReportOnlyAnalysis
# so someone can generate several reports (different scopes) in one sign-in
# session instead of the tool exiting immediately after the first report.
# Sign-in, discovery, the selection page, and the actual Graph pull are all
# mocked (same technique test-server.ps1 uses to override Start-Process --
# a function defined after dot-sourcing analyzer.ps1 shadows the real one
# for every call made afterward, including calls from inside
# Invoke-CaReportOnlyAnalysis) so this exercises only the loop's own control
# flow: how many times it asks, when it stops, and that each run gets its
# own output file rather than overwriting the previous one.

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\..\analyzer.ps1"

function Get-AccessToken { param($Method) return "fake-token" }
function Get-CaPolicies {
    param($Headers)
    return @{ Success = $true; Data = @([PSCustomObject]@{ id = "p1"; displayName = "Test Policy"; state = "enabledForReportingButNotEnforced" }) }
}
function Get-DiscoveryUsers {
    param($Headers)
    return @{ Success = $true; Data = @([PSCustomObject]@{ id = "u1"; displayName = "Alice"; userPrincipalName = "alice@contoso.com" }) }
}

$script:selectionServerCallCount = 0
function Start-SelectionServer {
    param($Users, $ReportOnlyPolicies)
    $script:selectionServerCallCount++
    return @{ all_users = $true; user_ids = @(); policy_ids = @("p1"); days = 7 }
}

$script:analysisRunOutputPaths = New-Object System.Collections.ArrayList
function Invoke-SingleAnalysisRun {
    param($Headers, $Selection, $ReportOnlyPolicies, $DiscoveredUsers, $OutputPath, $OpenBrowser)
    [void]$script:analysisRunOutputPaths.Add($OutputPath)
    return $OutputPath
}

$script:readHostResponses = New-Object System.Collections.Generic.Queue[string]
function Read-Host {
    param($Prompt)
    if ($script:readHostResponses.Count -gt 0) { return $script:readHostResponses.Dequeue() }
    return "n"
}

$script:failCount = 0
$script:passCount = 0
function Check {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { $script:passCount++; Write-Host "PASS: $Name" }
    else { $script:failCount++; Write-Host "FAIL: $Name" -ForegroundColor Red }
}

# --- Scenario 1: answering "y" twice then "n" runs the analysis 3 times ---
$script:selectionServerCallCount = 0
$script:analysisRunOutputPaths.Clear()
$script:readHostResponses.Enqueue("y")
$script:readHostResponses.Enqueue("Y")
$script:readHostResponses.Enqueue("n")

$result = Invoke-CaReportOnlyAnalysis -OutputPath "out.html" -OpenBrowser:$false

Check ($script:selectionServerCallCount -eq 3) "answering y/Y/n opens the selection page exactly 3 times, once per run"
Check ($script:analysisRunOutputPaths.Count -eq 3) "exactly 3 analysis runs happened"
Check ($script:analysisRunOutputPaths[0] -eq "out.html") "the first run keeps the exact requested output path"
Check ($script:analysisRunOutputPaths[1] -eq "out-2.html") "the second run gets its own -2 file instead of overwriting the first"
Check ($script:analysisRunOutputPaths[2] -eq "out-3.html") "the third run gets -3"
Check ($result -eq "out-3.html") "the function returns the path of the LAST run, not the first"

# --- Scenario 2: a blank answer (just pressing Enter) stops after one run ---
$script:selectionServerCallCount = 0
$script:analysisRunOutputPaths.Clear()
$script:readHostResponses.Enqueue("")

$result2 = Invoke-CaReportOnlyAnalysis -OutputPath "single.html" -OpenBrowser:$false

Check ($script:selectionServerCallCount -eq 1) "a blank answer (default No) runs the analysis exactly once, not zero and not more"
Check ($result2 -eq "single.html") "a single run keeps the original filename unchanged"

Write-Host ""
Write-Host "$script:passCount passed, $script:failCount failed" -ForegroundColor $(if ($script:failCount -eq 0) { "Green" } else { "Red" })
if ($script:failCount -gt 0) { exit 1 }
