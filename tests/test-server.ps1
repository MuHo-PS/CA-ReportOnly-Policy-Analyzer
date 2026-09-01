$ErrorActionPreference = "Stop"
. "$PSScriptRoot\..\analyzer.ps1"

function Start-Process { param($Path) Write-Host "(browser open suppressed for test): $Path" }

$users = @([PSCustomObject]@{ id = "u1"; displayName = "Alice" })
$groups = @([PSCustomObject]@{ id = "g1"; displayName = "Engineering" })
$policies = @([PSCustomObject]@{ id = "p1"; displayName = "Require MFA (report-only)" })
$testPort = 8799

# In-process background runspace for the test client -- avoids Start-Job's
# separate-process remoting overhead (and its own interactivity quirks,
# hit and worked around during this test's development).
$clientScript = {
    param($Port)
    Start-Sleep -Milliseconds 500
    try {
        $getResp = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
    } catch {
        return @{ ok = $false; stage = "GET"; error = $_.Exception.Message }
    }

    $payload = @{ all_users = $false; user_ids = @("u1"); group_ids = @(); policy_ids = @("p1"); days = 14 } | ConvertTo-Json
    try {
        $postResp = Invoke-RestMethod -Uri "http://127.0.0.1:$Port/submit" -Method Post -Body $payload -ContentType "application/json" -TimeoutSec 5 -ErrorAction Stop
    } catch {
        return @{ ok = $false; stage = "POST"; error = $_.Exception.Message }
    }

    return @{
        ok             = $true
        hasAlice       = [bool]($getResp.Content -match "Alice")
        hasEngineering = [bool]($getResp.Content -match "Engineering")
        hasPolicy      = [bool]($getResp.Content -match "Require MFA")
        postStatus     = $postResp.status
    }
}

$ps = [PowerShell]::Create()
[void]$ps.AddScript($clientScript).AddArgument($testPort)
$asyncHandle = $ps.BeginInvoke()

$selection = $null
$serverError = $null
try {
    $selection = Start-SelectionServer -Users $users -Groups $groups -ReportOnlyPolicies $policies -FixedPort $testPort -MaxWaitSeconds 15
} catch {
    $serverError = $_.Exception.Message
}

$clientCompleted = $asyncHandle.AsyncWaitHandle.WaitOne(10000)
if (-not $clientCompleted) {
    Write-Host "FAIL: client runspace did not finish in time" -ForegroundColor Red
    Write-Host "Server-side error (if any): $serverError"
    exit 1
}
$jobResult = $ps.EndInvoke($asyncHandle)[0]
$ps.Dispose()

Write-Host "Server-side error (if any): $serverError"
Write-Host "Client result: $($jobResult | ConvertTo-Json -Compress)"

if ($serverError) {
    Write-Host "FAIL: server-side timed out (client ok=$($jobResult.ok))" -ForegroundColor Red
    exit 1
}
if (-not $jobResult.ok) {
    Write-Host "FAIL: client failed at stage $($jobResult.stage): $($jobResult.error)" -ForegroundColor Red
    exit 1
}

$failCount = 0
function Check {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { Write-Host "PASS: $Name" }
    else { Write-Host "FAIL: $Name" -ForegroundColor Red; $script:failCount++ }
}

Check ($jobResult.hasAlice) "GET / includes the real user name"
Check ($jobResult.hasEngineering) "GET / includes the real group name"
Check ($jobResult.hasPolicy) "GET / includes the real policy name"
Check ($jobResult.postStatus -eq "ok") "POST /submit returned ok status"
Check ($selection.all_users -eq $false) "returned selection: all_users false"
Check ($selection.user_ids.Count -eq 1 -and $selection.user_ids[0] -eq "u1") "returned selection: correct user_ids"
Check ($selection.policy_ids.Count -eq 1 -and $selection.policy_ids[0] -eq "p1") "returned selection: correct policy_ids"
Check ($selection.days -eq 14) "returned selection: correct days"

Write-Host ""
if ($failCount -eq 0) { Write-Host "ALL SERVER TESTS PASSED" -ForegroundColor Green }
else { Write-Host "$failCount SERVER TESTS FAILED" -ForegroundColor Red; exit 1 }
