$ErrorActionPreference = "Stop"
. "$PSScriptRoot\..\analyzer.ps1"

$script:failCount = 0
$script:passCount = 0

function Assert-Equal {
    param($Actual, $Expected, [string]$Name)
    $actualJson = ($Actual | ConvertTo-Json -Depth 10 -Compress)
    $expectedJson = ($Expected | ConvertTo-Json -Depth 10 -Compress)
    if ($actualJson -eq $expectedJson) {
        $script:passCount++
        Write-Host "PASS: $Name"
    } else {
        $script:failCount++
        Write-Host "FAIL: $Name" -ForegroundColor Red
        Write-Host "  Expected: $expectedJson"
        Write-Host "  Actual:   $actualJson"
    }
}

function New-TestSignIn {
    param(
        [array]$Policies = @(),
        [string]$Created = "2026-08-01T10:00:00Z",
        [string]$App = "Office 365",
        [string]$City = "Cairo",
        [string]$Country = "EG",
        $Compliant = $null
    )
    return [PSCustomObject]@{
        createdDateTime = $Created
        appDisplayName  = $App
        location        = [PSCustomObject]@{ city = $City; countryOrRegion = $Country }
        deviceDetail    = [PSCustomObject]@{ isCompliant = $Compliant }
        appliedConditionalAccessPolicies = $Policies
    }
}

# --- Get-ResultBucket ---
Assert-Equal (Get-ResultBucket "reportOnlySuccess") "reportOnlySuccess" "known result passes through"
Assert-Equal (Get-ResultBucket "somethingNew") "unknownFutureValue" "unknown result maps to unknownFutureValue"

# --- Find-AppliedPolicyEntry ---
$signInWithPolicy = New-TestSignIn -Policies @(
    [PSCustomObject]@{ id = "p1"; result = "reportOnlySuccess" }
)
$entry = Find-AppliedPolicyEntry -SignIn $signInWithPolicy -PolicyId "p1"
Assert-Equal $entry.result "reportOnlySuccess" "finds matching policy entry"

$noEntry = Find-AppliedPolicyEntry -SignIn $signInWithPolicy -PolicyId "p-missing"
Assert-Equal $noEntry $null "returns null when policy absent"

# --- Get-AggregateCell: evaluated buckets ---
$signIns = @(
    (New-TestSignIn -Policies @([PSCustomObject]@{ id = "p1"; result = "reportOnlySuccess" })),
    (New-TestSignIn -Policies @([PSCustomObject]@{ id = "p1"; result = "reportOnlySuccess" })),
    (New-TestSignIn -Policies @([PSCustomObject]@{ id = "p1"; result = "reportOnlyFailure" }))
)
$cell = Get-AggregateCell -SignIns $signIns -PolicyId "p1"
Assert-Equal $cell.counts["reportOnlySuccess"] 2 "counts 2 reportOnlySuccess"
Assert-Equal $cell.counts["reportOnlyFailure"] 1 "counts 1 reportOnlyFailure"
Assert-Equal $cell.notEvaluatedCount 0 "zero not-evaluated when all matched"
Assert-Equal $cell.totalSignIns 3 "total sign-ins is 3"

# --- Get-AggregateCell: not-evaluated separated from results ---
$mixedSignIns = @(
    (New-TestSignIn -Policies @([PSCustomObject]@{ id = "p1"; result = "reportOnlySuccess" })),
    (New-TestSignIn -Policies @([PSCustomObject]@{ id = "other-policy"; result = "success" })),
    (New-TestSignIn -Policies @())
)
$mixedCell = Get-AggregateCell -SignIns $mixedSignIns -PolicyId "p1"
Assert-Equal $mixedCell.counts["reportOnlySuccess"] 1 "one evaluated result among mixed"
Assert-Equal $mixedCell.notEvaluatedCount 2 "two not-evaluated among mixed (never folded into counts)"

# --- Get-AggregateCell: unknown result bucket ---
$unknownCell = Get-AggregateCell -SignIns @((New-TestSignIn -Policies @([PSCustomObject]@{ id = "p1"; result = "somethingNew" }))) -PolicyId "p1"
Assert-Equal $unknownCell.counts["unknownFutureValue"] 1 "unknown result gets its own bucket"

# --- Get-AggregateCell: sample cap doesn't affect counts ---
$manySignIns = 1..10 | ForEach-Object { New-TestSignIn -Policies @([PSCustomObject]@{ id = "p1"; result = "reportOnlySuccess" }) }
$cappedCell = Get-AggregateCell -SignIns $manySignIns -PolicyId "p1" -MaxSamples 3
Assert-Equal $cappedCell.sampleEvents.Count 3 "sample events capped at 3"
Assert-Equal $cappedCell.totalSignIns 10 "total sign-ins unaffected by cap"
Assert-Equal $cappedCell.counts["reportOnlySuccess"] 10 "counts unaffected by cap"

# --- Get-UserPolicyMatrix: not-collected propagation ---
$users = @(
    [PSCustomObject]@{ id = "u1"; displayName = "Alice"; userPrincipalName = "alice@contoso.com" },
    [PSCustomObject]@{ id = "u2"; displayName = "Bob"; userPrincipalName = "bob@contoso.com" }
)
$policies = @([PSCustomObject]@{ id = "p1"; displayName = "Require MFA" })
$signInsByUser = @{ u1 = @((New-TestSignIn -Policies @([PSCustomObject]@{ id = "p1"; result = "reportOnlySuccess" }))) }
$collectionErrors = @{ u2 = "403 insufficient privileges" }

$matrix = Get-UserPolicyMatrix -Users $users -Policies $policies -SignInsByUser $signInsByUser -CollectionErrors $collectionErrors
Assert-Equal $matrix["u2"]["p1"].notCollected $true "u2 marked not collected"
Assert-Equal $matrix["u2"]["p1"].reason "403 insufficient privileges" "u2 carries the real reason"
Assert-Equal $matrix["u1"]["p1"].notCollected $false "u1 not marked not collected"
Assert-Equal $matrix["u1"]["p1"].counts["reportOnlySuccess"] 1 "u1's real cell computed correctly"

# --- Get-PolicyTotals ---
$totals = Get-PolicyTotals -Matrix $matrix -PolicyId "p1"
Assert-Equal $totals.notCollectedUsers 1 "one not-collected user counted"
Assert-Equal $totals.counts["reportOnlySuccess"] 1 "totals sum real counts only"

# --- Resolve-UserScope ---
$allScope = Resolve-UserScope -Selection @{ all_users = $true; user_ids = @(); group_ids = @() } -DiscoveredUsers $users -FetchGroupMembers { param($id) @() }
Assert-Equal $allScope.Count 2 "all_users returns full discovered list"

$specificScope = Resolve-UserScope -Selection @{ all_users = $false; user_ids = @("u2"); group_ids = @() } -DiscoveredUsers $users -FetchGroupMembers { param($id) @() }
Assert-Equal $specificScope.Count 1 "specific user scope returns only selected"
Assert-Equal $specificScope[0].id "u2" "specific user scope returns the right user"

$groupScope = Resolve-UserScope -Selection @{ all_users = $false; user_ids = @(); group_ids = @("g1") } `
    -DiscoveredUsers $users -FetchGroupMembers { param($id) @([PSCustomObject]@{ id = "u1" }) }
Assert-Equal $groupScope.Count 1 "group scope expands via fetch-members callback"
Assert-Equal $groupScope[0].id "u1" "group scope resolves to the right user"

$dedupedScope = Resolve-UserScope -Selection @{ all_users = $false; user_ids = @("u1"); group_ids = @("g1") } `
    -DiscoveredUsers $users -FetchGroupMembers { param($id) @([PSCustomObject]@{ id = "u1" }) }
Assert-Equal $dedupedScope.Count 1 "user selected individually AND via group is deduped"

Write-Host ""
Write-Host "$script:passCount passed, $script:failCount failed" -ForegroundColor $(if ($script:failCount -eq 0) { "Green" } else { "Red" })
if ($script:failCount -gt 0) { exit 1 }
