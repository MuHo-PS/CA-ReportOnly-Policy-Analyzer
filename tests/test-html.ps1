$ErrorActionPreference = "Stop"
. "$PSScriptRoot\..\analyzer.ps1"

$script:failCount = 0
$script:passCount = 0
function Assert-True {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { $script:passCount++; Write-Host "PASS: $Name" }
    else { $script:failCount++; Write-Host "FAIL: $Name" -ForegroundColor Red }
}

# --- Picker page: script-injection escaping ---
$trickyUsers = @([PSCustomObject]@{ id = "u1"; displayName = "Alice</script><script>alert(1)</script>" })
$policies = @([PSCustomObject]@{ id = "p1"; displayName = "Require MFA (report-only)" })
$pickerHtml = Get-PickerHtml -Users $trickyUsers -ReportOnlyPolicies $policies

Assert-True (-not $pickerHtml.Contains("</script><script>alert(1)</script>")) "picker escapes literal </script> in embedded JSON"
# Windows PowerShell's ConvertTo-Json Unicode-escapes < and > by default
# (< / >) -- verified empirically. This is a stronger, built-in
# safety net than the manual "</script>" -> "<\/script>" text-replace this
# project's earlier Python version needed (Python's json.dumps does not
# escape these). The manual .Replace() in ConvertTo-ScriptSafeJson is kept
# as defense-in-depth but is redundant given this native behavior.
$backslash = [char]92
$unicodeEscapedOpenAngle = "$backslash" + "u003c"
Assert-True ($pickerHtml.Contains($unicodeEscapedOpenAngle)) "picker's real (Unicode) escape form is present"
Assert-True ($pickerHtml.Contains("Require MFA (report-only)")) "picker embeds real policy name"

# --- Picker page: JSON actually parses back correctly (round-trip) ---
$normalUsers = @(
    [PSCustomObject]@{ id = "u1"; displayName = "Alice" },
    [PSCustomObject]@{ id = "u2"; displayName = "Bob" }
)
$normalHtml = Get-PickerHtml -Users $normalUsers -ReportOnlyPolicies $policies
Assert-True ($normalHtml.Contains('"Alice"') -and $normalHtml.Contains('"Bob"')) "picker embeds both user names"

# --- Picker page: no groups UI, and a policy search filter exists ---
Assert-True (-not $normalHtml.Contains('id="group-list"')) "groups UI has been removed from the picker"
Assert-True (-not $normalHtml.Contains('group_ids')) "group_ids no longer appears anywhere in the picker payload"
Assert-True ($normalHtml.Contains('id="policy-search"')) "a policy search input exists, matching the user search"
Assert-True ($normalHtml.Contains('getElementById("policy-search")') -and $normalHtml.Contains('addEventListener("input"')) "the policy search input is actually wired to filter the policy list"

# --- Report page: full render with real matrix data ---
$users = @([PSCustomObject]@{ id = "u1"; displayName = "Alice"; userPrincipalName = "alice@contoso.com" })
$signInsByUser = @{ u1 = @(
    [PSCustomObject]@{
        createdDateTime = "2026-08-01T10:00:00Z"
        appDisplayName  = "Office 365"
        location        = [PSCustomObject]@{ city = "Cairo"; countryOrRegion = "EG" }
        deviceDetail    = [PSCustomObject]@{ isCompliant = $true }
        appliedConditionalAccessPolicies = @([PSCustomObject]@{ id = "p1"; result = "reportOnlySuccess" })
    }
)}
$matrix = Get-UserPolicyMatrix -Users $users -Policies $policies -SignInsByUser $signInsByUser -CollectionErrors @{}
$meta = @{ totalSignIns = 1; requestedDays = 30 }
$reportHtml = Get-ReportHtml -Matrix $matrix -Users $users -Policies $policies -Meta $meta

Assert-True ($reportHtml.Contains("reportOnlySuccess")) "report embeds real aggregated result"
Assert-True ($reportHtml.Contains("escapeHtml")) "report defines the client-side HTML-escaping helper"
Assert-True ($reportHtml -match 'escapeHtml\(user\.displayName\)') "drill-down escapes user.displayName"
Assert-True ($reportHtml -match 'escapeHtml\(policy\.displayName\)') "drill-down escapes policy.displayName"
Assert-True ($reportHtml -match 'escapeHtml\(cell\.reason\)') "drill-down escapes cell.reason"
Assert-True ($reportHtml -match 'escapeHtml\(e\.timestamp\)') "sample-event fields escaped"

# --- Write-ReportHtml actually writes to disk ---
$tmpPath = [System.IO.Path]::GetTempFileName()
Write-ReportHtml -Html "<html>test</html>" -OutputPath $tmpPath
$written = Get-Content -Path $tmpPath -Raw
Assert-True ($written -eq "<html>test</html>") "Write-ReportHtml writes exact content"
Remove-Item $tmpPath -Force

Write-Host ""
Write-Host "$script:passCount passed, $script:failCount failed" -ForegroundColor $(if ($script:failCount -eq 0) { "Green" } else { "Red" })
if ($script:failCount -gt 0) { exit 1 }
