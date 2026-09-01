$ErrorActionPreference = "Stop"
. "$PSScriptRoot\..\analyzer.ps1"

$script:failCount = 0
function Check {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { Write-Host "PASS: $Name" }
    else { Write-Host "FAIL: $Name" -ForegroundColor Red; $script:failCount++ }
}

# This is the exact scenario that broke on a real tenant: a real Graph
# response for a single-page result (e.g. a small tenant's /users call, or
# any call that fits in one page) has NO "@odata.nextLink" property AT ALL
# -- Graph omits it rather than setting it null. Under Set-StrictMode
# -Version Latest (used in an earlier version of this file), accessing that
# missing property threw on every single-page call, and because the throw
# happened on a bare assignment outside any try/catch, $nextUri never
# actually got updated -- the while loop kept re-fetching the exact same
# URL forever. This test would have caught that before it shipped.

function Test-SinglePageNoNextLink {
    Mock-InvokeGraphRequestWithBackoff -Responses @(
        @{ Success = $true; Data = ([PSCustomObject]@{ value = @([PSCustomObject]@{ id = "1" }, [PSCustomObject]@{ id = "2" }) }) }
    )
    $result = Get-GraphAllPages -Uri "https://graph.microsoft.com/v1.0/users" -Headers @{}
    Check ($result.Success -eq $true) "single-page (no nextLink) call succeeds"
    Check ($result.Data.Count -eq 2) "single-page call returns exactly the 2 real items, not looped/duplicated"
    Check ($script:callCount -eq 1) "single-page call makes exactly ONE request, not an infinite loop"
}

function Test-MultiPageFollowsNextLink {
    Mock-InvokeGraphRequestWithBackoff -Responses @(
        @{ Success = $true; Data = ([PSCustomObject]@{
            value = @([PSCustomObject]@{ id = "1" })
            '@odata.nextLink' = "https://graph.microsoft.com/v1.0/users?skiptoken=abc"
        }) },
        @{ Success = $true; Data = ([PSCustomObject]@{ value = @([PSCustomObject]@{ id = "2" }) }) }
    )
    $result = Get-GraphAllPages -Uri "https://graph.microsoft.com/v1.0/users" -Headers @{}
    Check ($result.Success -eq $true) "multi-page call succeeds"
    Check ($result.Data.Count -eq 2) "multi-page call collects items across both pages"
    Check ($script:callCount -eq 2) "multi-page call makes exactly 2 requests, following nextLink once then stopping"
}

# Minimal mock: replaces the real HTTP function with a canned response
# sequence, and counts how many times it was actually called -- the call
# count is exactly what proves (or disproves) an infinite loop.
$script:callCount = 0
$script:mockResponses = @()
function Mock-InvokeGraphRequestWithBackoff {
    param([array]$Responses)
    $script:callCount = 0
    $script:mockResponses = $Responses
}
function global:Invoke-GraphRequestWithBackoff {
    param([string]$Method = "GET", [string]$Uri, [hashtable]$Headers, [int]$MaxRetries = 5)
    $script:callCount++
    if ($script:callCount -gt 5) { throw "Safety valve: more than 5 calls made -- likely an infinite loop, aborting the test." }
    $index = $script:callCount - 1
    if ($index -ge $script:mockResponses.Count) { throw "Mock ran out of canned responses -- likely an infinite loop." }
    return $script:mockResponses[$index]
}

Test-SinglePageNoNextLink
Test-MultiPageFollowsNextLink

Write-Host ""
if ($script:failCount -eq 0) { Write-Host "ALL PAGINATION TESTS PASSED" -ForegroundColor Green }
else { Write-Host "$($script:failCount) PAGINATION TESTS FAILED" -ForegroundColor Red; exit 1 }
