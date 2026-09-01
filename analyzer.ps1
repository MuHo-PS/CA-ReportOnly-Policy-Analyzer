<#
.SYNOPSIS
    CA Report-Only Policy Analyzer

.DESCRIPTION
    Reads real Entra ID sign-in log events and their own
    appliedConditionalAccessPolicies[] evaluation results to show which
    Conditional Access policies currently in report-only mode would
    actually have applied to a chosen set of users over a chosen window.

    It never infers or simulates a policy's behavior -- every number in
    the output traces back to a real Graph API evaluation result.
#>

Set-StrictMode -Version 1.0
$ProgressPreference = "SilentlyContinue"

# ===========================================================================
# Constants
# ===========================================================================

$Script:ClientId = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
$Script:Scopes = "AuditLog.Read.All Policy.Read.All User.Read.All Group.Read.All"
$Script:GraphBase = "https://graph.microsoft.com/v1.0"
$Script:AuthorityBase = "https://login.microsoftonline.com/organizations/oauth2/v2.0"

# Every result value appliedConditionalAccessPolicies[].result can hold,
# per Microsoft Graph's documented enum. Anything outside this set is
# bucketed as "unknownFutureValue" -- never dropped, never merged into an
# existing bucket.
$Script:KnownResults = @(
    "reportOnlySuccess", "reportOnlyFailure", "reportOnlyNotApplied", "reportOnlyInterrupted",
    "success", "failure", "notApplied", "notEnabled"
)

# ===========================================================================
# Auth: device code flow
# ===========================================================================

function Get-DeviceCodeToken {
    $body = @{ client_id = $Script:ClientId; scope = $Script:Scopes }
    $flow = Invoke-RestMethod -Method Post -Uri "$($Script:AuthorityBase)/devicecode" `
        -Body $body -ContentType "application/x-www-form-urlencoded"

    Write-Host ""
    Write-Host $flow.message -ForegroundColor Cyan
    Write-Host ""

    $interval = [int]$flow.interval
    if ($interval -lt 1) { $interval = 5 }
    $deadline = (Get-Date).AddSeconds([int]$flow.expires_in)

    while ((Get-Date) -lt $deadline) {
        Start-Sleep -Seconds $interval
        $tokenBody = @{
            grant_type  = "urn:ietf:params:oauth:grant-type:device_code"
            client_id   = $Script:ClientId
            device_code = $flow.device_code
        }
        try {
            $result = Invoke-RestMethod -Method Post -Uri "$($Script:AuthorityBase)/token" `
                -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            return $result.access_token
        } catch {
            $errBody = $null
            if ($_.ErrorDetails.Message) {
                try { $errBody = $_.ErrorDetails.Message | ConvertFrom-Json } catch { }
            }
            if ($null -eq $errBody) { throw }
            switch ($errBody.error) {
                "authorization_pending" { continue }
                "slow_down" { $interval += 5; continue }
                default { throw "Device code sign-in failed: $($errBody.error) - $($errBody.error_description)" }
            }
        }
    }
    throw "Device code sign-in timed out after $($flow.expires_in) seconds."
}

# ===========================================================================
# Graph HTTP: retry/backoff + pagination
#
# Returns a plain hashtable rather than throwing typed exceptions for
# expected HTTP failure modes (403 / 429 / other) -- callers branch on
# .Success/.Reason explicitly. This keeps error handling simple and
# version-safe rather than relying on custom PowerShell class hierarchies.
# ===========================================================================

function Invoke-GraphRequestWithBackoff {
    param(
        [string]$Method = "GET",
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [int]$MaxRetries = 5
    )
    for ($attempt = 1; $attempt -le $MaxRetries; $attempt++) {
        try {
            # -UseBasicParsing is required: without it, Windows PowerShell 5.1
            # tries to use Internet Explorer's DOM engine to parse the
            # response and can throw an interactive confirmation prompt on
            # first use in a session ("Script code in the web page might be
            # run..."). In any non-interactive context (or a fresh machine
            # where IE's first-run hasn't been dismissed) that prompt cannot
            # be answered and the call fails/hangs -- found only by actually
            # running this end to end, not by reading the code.
            $response = Invoke-WebRequest -Method $Method -Uri $Uri -Headers $Headers -UseBasicParsing -ErrorAction Stop
            $parsed = $response.Content | ConvertFrom-Json
            return @{ Success = $true; Data = $parsed }
        } catch {
            $webResponse = $_.Exception.Response
            if ($null -eq $webResponse) {
                return @{ Success = $false; Reason = "network"; Message = $_.Exception.Message }
            }
            $statusCode = [int]$webResponse.StatusCode

            if ($statusCode -eq 403) {
                return @{ Success = $false; Reason = "permission"; Message = "$Method $Uri -> 403" }
            }
            if ($statusCode -eq 429) {
                if ($attempt -eq $MaxRetries) {
                    return @{ Success = $false; Reason = "throttled"; Message = "$Method $Uri exhausted $MaxRetries retries on 429" }
                }
                $retryAfter = 1
                if ($webResponse.Headers["Retry-After"]) { $retryAfter = [int]$webResponse.Headers["Retry-After"] }
                Start-Sleep -Seconds $retryAfter
                continue
            }
            return @{ Success = $false; Reason = "other"; Message = "$Method $Uri -> $statusCode" }
        }
    }
}

function Get-GraphAllPages {
    param(
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        # Invoked after each page with the running total -- lets callers
        # print progress on long pulls (e.g. a full-tenant sign-in log
        # pull) without this function knowing anything about how progress
        # should be displayed.
        [scriptblock]$OnPage = $null
    )
    $results = New-Object System.Collections.ArrayList
    $nextUri = $Uri
    while ($nextUri) {
        $resp = Invoke-GraphRequestWithBackoff -Uri $nextUri -Headers $Headers
        if (-not $resp.Success) {
            return @{ Success = $false; Reason = $resp.Reason; Message = $resp.Message; Data = @($results) }
        }
        if ($resp.Data.value) {
            [void]$results.AddRange(@($resp.Data.value))
        }
        if ($OnPage) { & $OnPage $results.Count }
        $nextUri = $resp.Data.'@odata.nextLink'
    }
    return @{ Success = $true; Data = @($results) }
}

# ===========================================================================
# Discovery + sign-in log fetch functions
# ===========================================================================

function Get-CaPolicies {
    param([hashtable]$Headers)
    return Get-GraphAllPages -Uri "$($Script:GraphBase)/identity/conditionalAccess/policies" -Headers $Headers
}

function Get-DiscoveryUsers {
    param([hashtable]$Headers)
    return Get-GraphAllPages -Uri "$($Script:GraphBase)/users?`$select=id,displayName,userPrincipalName" -Headers $Headers
}

function Get-DiscoveryGroups {
    param([hashtable]$Headers)
    return Get-GraphAllPages -Uri "$($Script:GraphBase)/groups?`$select=id,displayName" -Headers $Headers
}

function Get-GroupMembers {
    param([hashtable]$Headers, [string]$GroupId)
    return Get-GraphAllPages -Uri "$($Script:GraphBase)/groups/$GroupId/members" -Headers $Headers
}

function Get-SignInsForUser {
    param([hashtable]$Headers, [string]$UserPrincipalName, [string]$SinceIso, [scriptblock]$OnPage = $null)
    $filter = "userPrincipalName eq '$UserPrincipalName' and createdDateTime ge $SinceIso"
    $encodedFilter = [System.Uri]::EscapeDataString($filter)
    return Get-GraphAllPages -Uri "$($Script:GraphBase)/auditLogs/signIns?`$filter=$encodedFilter" -Headers $Headers -OnPage $OnPage
}

function Get-SignInsAll {
    param([hashtable]$Headers, [string]$SinceIso, [scriptblock]$OnPage = $null)
    $filter = "createdDateTime ge $SinceIso"
    $encodedFilter = [System.Uri]::EscapeDataString($filter)
    return Get-GraphAllPages -Uri "$($Script:GraphBase)/auditLogs/signIns?`$filter=$encodedFilter" -Headers $Headers -OnPage $OnPage
}

# ===========================================================================
# Aggregation -- pure logic, no I/O. Three-state honesty:
# evaluated / not evaluated / not collected, never collapsed.
# ===========================================================================

function Get-ResultBucket {
    param([string]$RawResult)
    if ($Script:KnownResults -contains $RawResult) { return $RawResult }
    return "unknownFutureValue"
}

function Find-AppliedPolicyEntry {
    param($SignIn, [string]$PolicyId)
    if (-not $SignIn.appliedConditionalAccessPolicies) { return $null }
    foreach ($entry in $SignIn.appliedConditionalAccessPolicies) {
        if ($entry.id -eq $PolicyId) { return $entry }
    }
    return $null
}

function Format-SignInLocation {
    param($SignIn)
    $city = "Unknown"
    $country = "Unknown"
    if ($SignIn.location) {
        if ($SignIn.location.city) { $city = $SignIn.location.city }
        if ($SignIn.location.countryOrRegion) { $country = $SignIn.location.countryOrRegion }
    }
    return "$city, $country"
}

function Get-AggregateCell {
    param([array]$SignIns, [string]$PolicyId, [int]$MaxSamples = 50)

    $counts = @{}
    $notEvaluatedCount = 0
    $sampleEvents = New-Object System.Collections.ArrayList

    foreach ($signIn in $SignIns) {
        $entry = Find-AppliedPolicyEntry -SignIn $signIn -PolicyId $PolicyId
        if ($null -eq $entry) {
            $notEvaluatedCount++
            $bucket = "not_evaluated"
        } else {
            $bucket = Get-ResultBucket -RawResult $entry.result
            if ($counts.ContainsKey($bucket)) { $counts[$bucket]++ } else { $counts[$bucket] = 1 }
        }

        if ($sampleEvents.Count -lt $MaxSamples) {
            $deviceCompliant = $null
            if ($signIn.deviceDetail -and ($null -ne $signIn.deviceDetail.isCompliant)) {
                $deviceCompliant = $signIn.deviceDetail.isCompliant
            }
            [void]$sampleEvents.Add(@{
                timestamp        = $signIn.createdDateTime
                app              = $signIn.appDisplayName
                location         = Format-SignInLocation -SignIn $signIn
                deviceCompliant  = $deviceCompliant
                resultBucket     = $bucket
            })
        }
    }

    return @{
        notCollected      = $false
        counts            = $counts
        notEvaluatedCount = $notEvaluatedCount
        totalSignIns      = $SignIns.Count
        sampleEvents      = @($sampleEvents)
    }
}

function Get-UserPolicyMatrix {
    param(
        [array]$Users,
        [array]$Policies,
        [hashtable]$SignInsByUser,
        [hashtable]$CollectionErrors,
        [int]$MaxSamples = 50
    )
    $matrix = @{}
    foreach ($user in $Users) {
        $userId = $user.id
        $matrix[$userId] = @{}

        if ($CollectionErrors.ContainsKey($userId)) {
            $marker = @{ notCollected = $true; reason = $CollectionErrors[$userId] }
            foreach ($policy in $Policies) { $matrix[$userId][$policy.id] = $marker }
            continue
        }

        $signIns = @()
        if ($SignInsByUser.ContainsKey($userId)) { $signIns = $SignInsByUser[$userId] }
        foreach ($policy in $Policies) {
            $matrix[$userId][$policy.id] = Get-AggregateCell -SignIns $signIns -PolicyId $policy.id -MaxSamples $MaxSamples
        }
    }
    return $matrix
}

function Get-PolicyTotals {
    param([hashtable]$Matrix, [string]$PolicyId)
    $counts = @{}
    $notEvaluatedCount = 0
    $notCollectedUsers = 0
    $totalSignIns = 0

    foreach ($userId in $Matrix.Keys) {
        $cell = $Matrix[$userId][$PolicyId]
        if ($cell.notCollected) {
            $notCollectedUsers++
            continue
        }
        foreach ($bucket in $cell.counts.Keys) {
            if ($counts.ContainsKey($bucket)) { $counts[$bucket] += $cell.counts[$bucket] }
            else { $counts[$bucket] = $cell.counts[$bucket] }
        }
        $notEvaluatedCount += $cell.notEvaluatedCount
        $totalSignIns += $cell.totalSignIns
    }

    return @{
        counts            = $counts
        notEvaluatedCount = $notEvaluatedCount
        notCollectedUsers = $notCollectedUsers
        totalSignIns      = $totalSignIns
    }
}

# ===========================================================================
# User-scope resolution (all / specific users / groups, deduped)
# ===========================================================================

function Resolve-UserScope {
    param(
        [hashtable]$Selection,
        [array]$DiscoveredUsers,
        [scriptblock]$FetchGroupMembers
    )
    # PowerShell gotcha: a bare array `return`ed from a function is silently
    # unwrapped to a scalar when it holds exactly one (or zero) elements.
    # Every return path here uses the unary comma operator `,` to force the
    # caller to always receive a real array, regardless of element count.
    if ($Selection.all_users) { return , @($DiscoveredUsers) }

    $usersById = @{}
    foreach ($u in $DiscoveredUsers) { $usersById[$u.id] = $u }

    $selectedIds = New-Object System.Collections.Specialized.OrderedDictionary

    foreach ($userId in $Selection.user_ids) {
        if ($usersById.ContainsKey($userId)) { $selectedIds[$userId] = $true }
    }

    foreach ($groupId in $Selection.group_ids) {
        $members = & $FetchGroupMembers $groupId
        foreach ($member in $members) {
            if ($usersById.ContainsKey($member.id)) { $selectedIds[$member.id] = $true }
        }
    }

    $result = New-Object System.Collections.ArrayList
    foreach ($id in $selectedIds.Keys) { [void]$result.Add($usersById[$id]) }
    return , @($result)
}

# ===========================================================================
# Shared HTML helpers
# ===========================================================================

# JSON destined for an inline <script> block must never let a literal
# "</script>" close the tag early -- this bit us for real in an earlier
# version of this tool, so it's applied everywhere JSON is embedded,
# proactively, not discovered after the fact.
function ConvertTo-ScriptSafeJson {
    param($InputObject, [int]$Depth = 12)
    # Real PowerShell quirk, caught by testing: ConvertTo-Json on an empty
    # array returns $null, not the string "[]" -- if unhandled, any list
    # that happens to be empty (zero groups, zero policies, etc.) would
    # embed literal `null` (or crash here) instead of a valid empty array
    # the page's JS can safely iterate.
    if ($InputObject -is [array] -and $InputObject.Count -eq 0) {
        return "[]"
    }
    $json = $InputObject | ConvertTo-Json -Depth $Depth -Compress
    if ($null -eq $json) { return "[]" }
    return $json.Replace("</script>", "<\/script>")
}

$Script:SharedPageStyle = @'
<style>
  :root {
    --bg: #f7f8fa;
    --card: #ffffff;
    --border: #e3e6ea;
    --text: #1c2128;
    --text-muted: #5b6572;
    --accent: #2f6fed;
    --accent-soft: #eaf1fe;
    --ok: #1a7f4b;
    --ok-soft: #e6f6ee;
    --bad: #c4342f;
    --bad-soft: #fbeaea;
    --warn: #b5760a;
    --warn-soft: #fdf3e3;
    --neutral-soft: #eef0f2;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg);
    color: var(--text);
    margin: 0;
    padding: 2.5rem 1.5rem 4rem;
  }
  .page { max-width: 960px; margin: 0 auto; }
  h1 {
    font-size: 1.75rem;
    font-weight: 700;
    margin: 0 0 0.25rem;
    letter-spacing: -0.01em;
  }
  .subtitle { color: var(--text-muted); margin: 0 0 2rem; font-size: 0.95rem; }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 12px;
    padding: 1.25rem 1.5rem;
    margin-bottom: 1.25rem;
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.04);
  }
  .card-title {
    font-weight: 600;
    font-size: 0.95rem;
    margin: 0 0 0.9rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }
  .card-title .accent-dot {
    width: 8px; height: 8px; border-radius: 50%;
    background: var(--accent); flex-shrink: 0;
  }
  input[type="search"], input[type="number"] {
    width: 100%;
    padding: 0.55rem 0.75rem;
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 0.9rem;
    background: var(--bg);
    color: var(--text);
    margin-bottom: 0.6rem;
  }
  input[type="search"]:focus, input[type="number"]:focus {
    outline: none;
    border-color: var(--accent);
    background: var(--card);
  }
  .scroll-list {
    max-height: 230px;
    overflow-y: auto;
    border: 1px solid var(--border);
    border-radius: 8px;
    background: var(--bg);
  }
  .scroll-list label {
    display: flex;
    align-items: center;
    gap: 0.55rem;
    padding: 0.45rem 0.75rem;
    font-size: 0.88rem;
    cursor: pointer;
    border-bottom: 1px solid var(--border);
  }
  .scroll-list label:last-child { border-bottom: none; }
  .scroll-list label:hover { background: var(--accent-soft); }
  .scroll-list input[type="checkbox"] { flex-shrink: 0; accent-color: var(--accent); }
  .all-users-row {
    display: flex; align-items: center; gap: 0.55rem;
    padding: 0.5rem 0.1rem 0.75rem; font-size: 0.9rem; font-weight: 500;
  }
  .all-users-row input { accent-color: var(--accent); }
  .badge {
    display: inline-block;
    padding: 0.12rem 0.55rem;
    border-radius: 999px;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.01em;
  }
  .badge-report-only { background: var(--warn-soft); color: var(--warn); }
  .badge-enabled { background: var(--ok-soft); color: var(--ok); }
  .policy-name { flex: 1; }
  .days-row { display: flex; align-items: center; gap: 0.75rem; }
  .days-row input { width: 90px; margin-bottom: 0; }
  .hint { color: var(--text-muted); font-size: 0.82rem; margin-top: 0.4rem; }
  .primary-btn {
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 0.7rem 1.6rem;
    font-size: 0.95rem;
    font-weight: 600;
    cursor: pointer;
    box-shadow: 0 1px 2px rgba(16, 24, 40, 0.08);
  }
  .primary-btn:hover { filter: brightness(1.06); }
  .primary-btn:disabled { opacity: 0.6; cursor: not-allowed; }
  #status { margin-top: 0.9rem; font-size: 0.88rem; color: var(--text-muted); }
  .caveats {
    background: var(--warn-soft);
    border: 1px solid #eccf94;
    border-radius: 10px;
    padding: 1rem 1.25rem;
    margin-top: 1.5rem;
  }
  .caveats strong { display: block; margin-bottom: 0.4rem; }
  .caveats ul { margin: 0; padding-left: 1.2rem; font-size: 0.85rem; color: var(--text-muted); }
  .caveats li { margin-bottom: 0.3rem; }
</style>
'@

# ===========================================================================
# Picker page
# ===========================================================================

function Get-PickerHtml {
    param([array]$Users, [array]$Groups, [array]$ReportOnlyPolicies)

    $usersJson = ConvertTo-ScriptSafeJson -InputObject @($Users)
    $groupsJson = ConvertTo-ScriptSafeJson -InputObject @($Groups)
    $policiesJson = ConvertTo-ScriptSafeJson -InputObject @($ReportOnlyPolicies)

    $policyCountNote = if ($ReportOnlyPolicies.Count -eq 0) {
        "This tenant has no Conditional Access policies currently in report-only mode."
    } else {
        "$($ReportOnlyPolicies.Count) report-only polic$(if ($ReportOnlyPolicies.Count -eq 1) { 'y' } else { 'ies' }) found in this tenant."
    }

    return @"
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CA Report-Only Policy Analyzer</title>
$Script:SharedPageStyle
</head>
<body>
<div class="page">
  <h1>CA Report-Only Policy Analyzer</h1>
  <p class="subtitle">Choose who and what to analyze, then generate the report.</p>

  <div class="card">
    <div class="card-title"><span class="accent-dot"></span>Users</div>
    <label class="all-users-row"><input type="checkbox" id="all-users-checkbox"> All users</label>
    <input type="search" id="user-search" placeholder="Search users...">
    <div class="scroll-list" id="user-list"></div>
  </div>

  <div class="card">
    <div class="card-title"><span class="accent-dot"></span>Groups</div>
    <input type="search" id="group-search" placeholder="Search groups...">
    <div class="scroll-list" id="group-list"></div>
    <p class="hint">Selecting a group includes its current members at run time.</p>
  </div>

  <div class="card">
    <div class="card-title"><span class="accent-dot"></span>Report-only policies</div>
    <p class="hint" style="margin-top:0;margin-bottom:0.75rem;">$policyCountNote</p>
    <div class="scroll-list" id="policy-list"></div>
  </div>

  <div class="card">
    <div class="card-title"><span class="accent-dot"></span>Day range</div>
    <div class="days-row">
      <label for="days-input">Days back:</label>
      <input type="number" id="days-input" value="30" min="1">
    </div>
    <p class="hint" id="retention-warning" style="display:none;color:var(--warn);">
      Entra ID sign-in log retention is typically 30 days -- results beyond that will likely be empty.
    </p>
  </div>

  <button class="primary-btn" id="generate-btn">Generate report</button>
  <div id="status"></div>

  <div class="caveats">
    <strong>Before you run this</strong>
    <ul>
      <li>Only Conditional Access policies currently in report-only mode are shown -- this tool measures what they would have done, not enforced policies.</li>
      <li>A missing policy entry on a sign-in means the policy's conditions did not match that specific request -- it is not evidence the policy is broken.</li>
      <li>Graph exposes only the tenant's current policy list; if a policy's mode changed during the window you're analyzing, this tool cannot detect that.</li>
    </ul>
  </div>
</div>

<script>
  const USERS = $usersJson;
  const GROUPS = $groupsJson;
  const POLICIES = $policiesJson;

  function renderCheckboxList(container, items, role) {
    container.innerHTML = "";
    for (const item of items) {
      const label = document.createElement("label");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = item.id;
      checkbox.dataset.role = role;
      label.appendChild(checkbox);
      const nameSpan = document.createElement("span");
      nameSpan.className = "policy-name";
      nameSpan.textContent = item.displayName;
      label.appendChild(nameSpan);
      container.appendChild(label);
    }
  }

  const userList = document.getElementById("user-list");
  const groupList = document.getElementById("group-list");
  const policyList = document.getElementById("policy-list");

  renderCheckboxList(userList, USERS, "user");
  renderCheckboxList(groupList, GROUPS, "group");
  renderCheckboxList(policyList, POLICIES, "policy");

  document.getElementById("user-search").addEventListener("input", (e) => {
    const term = e.target.value.toLowerCase();
    renderCheckboxList(userList, USERS.filter(u => (u.displayName || "").toLowerCase().includes(term)), "user");
  });
  document.getElementById("group-search").addEventListener("input", (e) => {
    const term = e.target.value.toLowerCase();
    renderCheckboxList(groupList, GROUPS.filter(g => (g.displayName || "").toLowerCase().includes(term)), "group");
  });

  const daysInput = document.getElementById("days-input");
  const retentionWarning = document.getElementById("retention-warning");
  daysInput.addEventListener("input", () => {
    retentionWarning.style.display = Number(daysInput.value) > 30 ? "block" : "none";
  });

  const allUsersCheckbox = document.getElementById("all-users-checkbox");
  allUsersCheckbox.addEventListener("change", () => {
    userList.querySelectorAll("input").forEach(cb => cb.disabled = allUsersCheckbox.checked);
    document.getElementById("user-search").disabled = allUsersCheckbox.checked;
  });

  const generateBtn = document.getElementById("generate-btn");
  generateBtn.addEventListener("click", () => {
    const allUsers = allUsersCheckbox.checked;
    const selectedUserIds = Array.from(userList.querySelectorAll("input:checked")).map(cb => cb.value);
    const selectedGroupIds = Array.from(groupList.querySelectorAll("input:checked")).map(cb => cb.value);
    const selectedPolicyIds = Array.from(policyList.querySelectorAll("input:checked")).map(cb => cb.value);

    if (!allUsers && selectedUserIds.length === 0 && selectedGroupIds.length === 0) {
      document.getElementById("status").textContent = "Select at least one user, group, or \"All users\".";
      return;
    }
    if (selectedPolicyIds.length === 0) {
      document.getElementById("status").textContent = "Select at least one report-only policy.";
      return;
    }

    const payload = {
      all_users: allUsers,
      user_ids: selectedUserIds,
      group_ids: selectedGroupIds,
      policy_ids: selectedPolicyIds,
      days: Number(daysInput.value),
    };

    generateBtn.disabled = true;
    document.getElementById("status").textContent = "Submitting selection...";
    fetch("/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then(() => {
      document.getElementById("status").textContent =
        "Selection received. Pulling sign-in logs now -- watch the terminal window for progress, then this tab will not be needed. You can close it.";
    }).catch(() => {
      generateBtn.disabled = false;
      document.getElementById("status").textContent = "Submit failed -- check the terminal window.";
    });
  });
</script>
</body>
</html>
"@
}

# ===========================================================================
# Transient loopback selection server
# ===========================================================================

function Start-SelectionServer {
    param(
        [array]$Users,
        [array]$Groups,
        [array]$ReportOnlyPolicies,
        # Forces a specific port instead of scanning -- used by tests for a
        # deterministic, immediately-known address. Real runs omit this.
        [Nullable[int]]$FixedPort = $null,
        # Real runs wait indefinitely for a human to submit the picker.
        # Tests pass a small value so a bug here fails fast instead of
        # hanging for minutes.
        [int]$MaxWaitSeconds = 0
    )

    $listener = New-Object System.Net.HttpListener
    $port = $null
    $portsToTry = if ($FixedPort) { @($FixedPort) } else { 8765..8865 }
    foreach ($candidatePort in $portsToTry) {
        try {
            $listener.Prefixes.Clear()
            $listener.Prefixes.Add("http://127.0.0.1:$candidatePort/")
            $listener.Start()
            $port = $candidatePort
            break
        } catch {
            continue
        }
    }
    if (-not $port) { throw "Could not bind a local port for the selection page." }

    $pageHtml = Get-PickerHtml -Users $Users -Groups $Groups -ReportOnlyPolicies $ReportOnlyPolicies
    $url = "http://127.0.0.1:$port/"

    try { Start-Process $url | Out-Null } catch {
        Write-Host "Could not open a browser automatically -- open this URL manually: $url" -ForegroundColor Yellow
    }

    # Async accept in a bounded polling loop rather than a single opaque
    # blocking GetContext() call -- chosen after a real blocking call
    # proved much harder to test/debug reliably. IMPORTANT correctness
    # note, found by testing: BeginGetContext must be called exactly ONCE
    # per connection actually accepted, then polled via WaitOne on THAT
    # SAME IAsyncResult until it completes -- calling BeginGetContext
    # again on every poll tick (discarding the previous pending result)
    # breaks the listener's internal accept state and connections stop
    # arriving. Only start a new BeginGetContext after EndGetContext has
    # completed the previous one.
    $selection = $null
    $deadline = if ($MaxWaitSeconds -gt 0) { (Get-Date).AddSeconds($MaxWaitSeconds) } else { $null }
    $pendingAccept = $listener.BeginGetContext($null, $null)

    while ($null -eq $selection) {
        if ($deadline -and (Get-Date) -gt $deadline) {
            $listener.Stop(); $listener.Close()
            throw "Timed out after $MaxWaitSeconds second(s) waiting for a selection to be submitted."
        }

        $gotOne = $pendingAccept.AsyncWaitHandle.WaitOne(500)
        if (-not $gotOne) { continue }

        $context = $listener.EndGetContext($pendingAccept)
        $pendingAccept = $listener.BeginGetContext($null, $null)
        $request = $context.Request
        $response = $context.Response

        try {
            if ($request.HttpMethod -eq "GET" -and $request.Url.AbsolutePath -eq "/") {
                $buffer = [System.Text.Encoding]::UTF8.GetBytes($pageHtml)
                $response.ContentType = "text/html; charset=utf-8"
                $response.ContentLength64 = $buffer.Length
                $response.OutputStream.Write($buffer, 0, $buffer.Length)
            }
            elseif ($request.HttpMethod -eq "POST" -and $request.Url.AbsolutePath -eq "/submit") {
                $reader = New-Object System.IO.StreamReader($request.InputStream, $request.ContentEncoding)
                $body = $reader.ReadToEnd()
                $parsed = $null
                try { $parsed = $body | ConvertFrom-Json -ErrorAction Stop } catch { $parsed = $null }

                if ($null -eq $parsed) {
                    $response.StatusCode = 400
                } else {
                    # Normalize into a plain hashtable so downstream code
                    # doesn't depend on PSCustomObject-specific behavior.
                    $selection = @{
                        all_users  = [bool]$parsed.all_users
                        user_ids   = @($parsed.user_ids)
                        group_ids  = @($parsed.group_ids)
                        policy_ids = @($parsed.policy_ids)
                        days       = [int]$parsed.days
                    }
                    $okBytes = [System.Text.Encoding]::UTF8.GetBytes('{"status":"ok"}')
                    $response.ContentType = "application/json"
                    $response.ContentLength64 = $okBytes.Length
                    $response.OutputStream.Write($okBytes, 0, $okBytes.Length)
                }
            }
            else {
                $response.StatusCode = 404
            }
        } finally {
            $response.OutputStream.Close()
        }
    }

    $listener.Stop()
    $listener.Close()
    return $selection
}

# ===========================================================================
# Report renderer
# ===========================================================================

$Script:ReportPageStyle = @'
<style>
  :root {
    --bg: #f7f8fa; --card: #ffffff; --border: #e3e6ea;
    --text: #1c2128; --text-muted: #5b6572;
    --accent: #2f6fed; --accent-soft: #eaf1fe;
    --ok: #1a7f4b; --ok-soft: #e6f6ee;
    --bad: #c4342f; --bad-soft: #fbeaea;
    --warn: #b5760a; --warn-soft: #fdf3e3;
    --neutral: #6b7280; --neutral-soft: #eef0f2;
  }
  * { box-sizing: border-box; }
  body {
    font-family: -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    background: var(--bg); color: var(--text);
    margin: 0; padding: 2.5rem 1.5rem 4rem;
  }
  .page { max-width: 1100px; margin: 0 auto; }
  h1 { font-size: 1.75rem; font-weight: 700; margin: 0 0 1.5rem; letter-spacing: -0.01em; }
  h2 { font-size: 1.15rem; font-weight: 700; margin: 2rem 0 0.9rem; }
  .cards { display: flex; gap: 0.9rem; flex-wrap: wrap; margin-bottom: 0.5rem; }
  .stat-card {
    background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 0.9rem 1.2rem; min-width: 140px;
    box-shadow: 0 1px 2px rgba(16,24,40,0.04);
  }
  .stat-card .label { font-size: 0.78rem; color: var(--text-muted); margin-bottom: 0.25rem; }
  .stat-card .value { font-size: 1.5rem; font-weight: 700; }
  .stat-card.warn .value { color: var(--warn); }
  table { border-collapse: collapse; width: 100%; background: var(--card); border-radius: 12px; overflow: hidden; }
  th, td { border: 1px solid var(--border); padding: 0.6rem 0.8rem; text-align: left; font-size: 0.85rem; vertical-align: top; }
  th { background: var(--neutral-soft); font-weight: 600; }
  td.cell-would-apply { background: var(--ok-soft); }
  td.cell-would-not-apply { background: var(--bad-soft); }
  td.cell-mixed { background: var(--warn-soft); }
  td.cell-not-collected { background: var(--neutral-soft); color: var(--text-muted); font-style: italic; }
  td.matrix-cell { cursor: pointer; }
  td.matrix-cell:hover { filter: brightness(0.97); }
  #drill-down {
    display: none; background: var(--card); border: 1px solid var(--border); border-radius: 12px;
    padding: 1rem 1.25rem; margin-top: 0.9rem; font-size: 0.85rem;
  }
  #drill-down table { margin-top: 0.6rem; }
  .policy-chart { background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 1rem 1.25rem; margin-bottom: 0.9rem; }
  .policy-chart h3 { margin: 0 0 0.75rem; font-size: 0.95rem; }
  .bar-row { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 0.35rem; font-size: 0.82rem; }
  .bar-label { width: 180px; flex-shrink: 0; color: var(--text-muted); }
  .bar-track { flex: 1; background: var(--neutral-soft); border-radius: 4px; overflow: hidden; height: 16px; }
  .bar-fill { height: 100%; background: var(--accent); }
  .bar-fill.not-evaluated { background: var(--neutral); }
  .bar-count { width: 40px; text-align: right; }
  .caveats {
    background: var(--warn-soft); border: 1px solid #eccf94; border-radius: 10px;
    padding: 1rem 1.25rem; margin-top: 2rem;
  }
  .caveats strong { display: block; margin-bottom: 0.4rem; }
  .caveats ul { margin: 0; padding-left: 1.2rem; font-size: 0.85rem; color: var(--text-muted); }
  .caveats li { margin-bottom: 0.3rem; }
</style>
'@

function Get-ReportHtml {
    param([hashtable]$Matrix, [array]$Users, [array]$Policies, [hashtable]$Meta)

    $policyTotals = @{}
    foreach ($policy in $Policies) {
        $policyTotals[$policy.id] = Get-PolicyTotals -Matrix $Matrix -PolicyId $policy.id
    }

    $reportData = @{
        users        = @($Users)
        policies     = @($Policies)
        matrix       = $Matrix
        policyTotals = $policyTotals
        meta         = $Meta
    }
    $reportJson = ConvertTo-ScriptSafeJson -InputObject $reportData

    # NOTE: this is a single-quoted (non-interpolating) here-string on
    # purpose. PowerShell's interpolating `@" ... "@` here-strings treat
    # `${...}` as ITS OWN variable-interpolation syntax -- which collides
    # head-on with JavaScript's `${...}` template-literal syntax used
    # throughout the embedded script below. That collision was caught by
    # testing (it crashed with "variable not set" errors), not guessed.
    # Real values are substituted afterward via .Replace() on placeholder
    # tokens instead -- same pattern the project's earlier Python version
    # used for exactly this reason.
    $template = @'
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CA Report-Only Policy Analyzer -- Report</title>
__REPORT_STYLE__
</head>
<body>
<div class="page">
  <h1>CA Report-Only Policy Analyzer -- Report</h1>
  <div class="cards" id="summary-cards"></div>

  <h2>User &times; Policy Matrix</h2>
  <table id="matrix-table"></table>
  <div id="drill-down"></div>

  <h2>Per-Policy Result Distribution</h2>
  <div id="policy-charts"></div>

  <div class="caveats">
    <strong>Caveats</strong>
    <ul>
      <li>Results assume each policy's report-only/enforced mode was constant across the analyzed window -- Graph only exposes the current policy list, not its history.</li>
      <li>Interactive user sign-ins only; workload-identity/service-principal sign-ins are not included.</li>
      <li>"Not evaluated" means this policy's conditions (app, resource, risk level, scope, etc.) did not match that specific sign-in -- it is never the same thing as "would not apply to this user in general," and it is not evidence anything is broken.</li>
      <li>This tool does not independently verify whether the tenant's sign-in log retention actually covered the full requested day range.</li>
    </ul>
  </div>
</div>

<script>
  const REPORT_DATA = __REPORT_DATA__;

  function escapeHtml(str) {
    const div = document.createElement("div");
    div.textContent = (str === null || str === undefined) ? "" : String(str);
    return div.innerHTML;
  }

  function countNotCollectedUsers() {
    let count = 0;
    for (const userId of Object.keys(REPORT_DATA.matrix)) {
      const cells = Object.values(REPORT_DATA.matrix[userId]);
      if (cells.some(c => c.notCollected)) count++;
    }
    return count;
  }

  function renderSummaryCards() {
    const container = document.getElementById("summary-cards");
    const notCollected = countNotCollectedUsers();
    const cards = [
      ["Sign-ins pulled", REPORT_DATA.meta.totalSignIns, false],
      ["Users analyzed", REPORT_DATA.users.length, false],
      ["Not collected", notCollected, notCollected > 0],
      ["Report-only policies", REPORT_DATA.policies.length, false],
      ["Requested days", REPORT_DATA.meta.requestedDays, false],
    ];
    for (const [label, value, isWarn] of cards) {
      const div = document.createElement("div");
      div.className = "stat-card" + (isWarn ? " warn" : "");
      div.innerHTML = `<div class="label">${escapeHtml(label)}</div><div class="value">${escapeHtml(value)}</div>`;
      container.appendChild(div);
    }
  }

  function dominantClass(cell) {
    if (cell.notCollected) return "cell-not-collected";
    const counts = cell.counts || {};
    const applyCount = (counts.reportOnlySuccess || 0) + (counts.success || 0);
    const notApplyCount = (counts.reportOnlyNotApplied || 0) + (counts.notApplied || 0) +
                           (counts.reportOnlyFailure || 0) + (counts.failure || 0);
    if (applyCount > 0 && notApplyCount === 0) return "cell-would-apply";
    if (notApplyCount > 0 && applyCount === 0) return "cell-would-not-apply";
    if (applyCount > 0 && notApplyCount > 0) return "cell-mixed";
    return "cell-not-collected";
  }

  function cellLabel(cell) {
    if (cell.notCollected) return "Not collected";
    const total = Object.values(cell.counts || {}).reduce((a, b) => a + b, 0);
    return `${total} evaluated / ${cell.notEvaluatedCount} not evaluated`;
  }

  function renderMatrix() {
    const table = document.getElementById("matrix-table");
    const headerRow = document.createElement("tr");
    headerRow.appendChild(document.createElement("th"));
    for (const policy of REPORT_DATA.policies) {
      const th = document.createElement("th");
      th.textContent = policy.displayName;
      headerRow.appendChild(th);
    }
    table.appendChild(headerRow);

    for (const user of REPORT_DATA.users) {
      const row = document.createElement("tr");
      const nameCell = document.createElement("td");
      nameCell.textContent = user.displayName;
      row.appendChild(nameCell);
      for (const policy of REPORT_DATA.policies) {
        const cell = REPORT_DATA.matrix[user.id][policy.id];
        const td = document.createElement("td");
        td.className = "matrix-cell " + dominantClass(cell);
        td.textContent = cellLabel(cell);
        td.addEventListener("click", () => showDrillDown(user, policy, cell));
        row.appendChild(td);
      }
      table.appendChild(row);
    }
  }

  function showDrillDown(user, policy, cell) {
    const el = document.getElementById("drill-down");
    if (cell.notCollected) {
      el.innerHTML = `<strong>${escapeHtml(user.displayName)} / ${escapeHtml(policy.displayName)}</strong>: not collected -- ${escapeHtml(cell.reason)}`;
    } else {
      const rows = (cell.sampleEvents || []).map(e =>
        `<tr><td>${escapeHtml(e.timestamp)}</td><td>${escapeHtml(e.app)}</td><td>${escapeHtml(e.location)}</td><td>${escapeHtml(e.resultBucket)}</td></tr>`
      ).join("");
      el.innerHTML = `<strong>${escapeHtml(user.displayName)} / ${escapeHtml(policy.displayName)}</strong> -- sample events:
        <table><tr><th>Time</th><th>App</th><th>Location</th><th>Result</th></tr>${rows}</table>`;
    }
    el.style.display = "block";
  }

  function renderPolicyCharts() {
    const container = document.getElementById("policy-charts");
    for (const policy of REPORT_DATA.policies) {
      const totals = REPORT_DATA.policyTotals[policy.id];
      const total = Object.values(totals.counts).reduce((a, b) => a + b, 0) + totals.notEvaluatedCount;
      const div = document.createElement("div");
      div.className = "policy-chart";
      let inner = `<h3>${escapeHtml(policy.displayName)}</h3>`;
      for (const [bucket, count] of Object.entries(totals.counts)) {
        const pct = total > 0 ? Math.round((count / total) * 100) : 0;
        inner += `<div class="bar-row"><div class="bar-label">${escapeHtml(bucket)}</div><div class="bar-track"><div class="bar-fill" style="width:${pct}%"></div></div><div class="bar-count">${count}</div></div>`;
      }
      const naPct = total > 0 ? Math.round((totals.notEvaluatedCount / total) * 100) : 0;
      inner += `<div class="bar-row"><div class="bar-label">not_evaluated</div><div class="bar-track"><div class="bar-fill not-evaluated" style="width:${naPct}%"></div></div><div class="bar-count">${totals.notEvaluatedCount}</div></div>`;
      if (totals.notCollectedUsers > 0) {
        inner += `<div class="bar-row" style="color:var(--text-muted);">${totals.notCollectedUsers} user(s) not collected for this policy</div>`;
      }
      div.innerHTML = inner;
      container.appendChild(div);
    }
  }

  renderSummaryCards();
  renderMatrix();
  renderPolicyCharts();
</script>
</body>
</html>
'@

    $html = $template.Replace("__REPORT_STYLE__", $Script:ReportPageStyle).Replace("__REPORT_DATA__", $reportJson)
    return $html
}

function Write-ReportHtml {
    param([string]$Html, [string]$OutputPath)
    Set-Content -Path $OutputPath -Value $Html -Encoding UTF8 -NoNewline
}

# ===========================================================================
# Main orchestration
# ===========================================================================

function Invoke-CaReportOnlyAnalysis {
    param(
        [string]$OutputPath = "ca-report-only-analysis.html",
        [switch]$OpenBrowser = $true
    )

    Write-Host "=== CA Report-Only Policy Analyzer ===" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Signing in..."
    $token = Get-DeviceCodeToken
    $headers = @{ Authorization = "Bearer $token" }
    Write-Host "Signed in." -ForegroundColor Green
    Write-Host ""

    Write-Host "Discovering Conditional Access policies, users, and groups..."
    $policiesResp = Get-CaPolicies -Headers $headers
    if (-not $policiesResp.Success) {
        throw "Could not read Conditional Access policies: $($policiesResp.Reason) -- $($policiesResp.Message)"
    }
    $reportOnlyPolicies = @($policiesResp.Data | Where-Object { $_.state -eq "enabledForReportingButNotEnforced" })
    Write-Host "  $($reportOnlyPolicies.Count) report-only polic$(if ($reportOnlyPolicies.Count -eq 1) { 'y' } else { 'ies' }) found (of $($policiesResp.Data.Count) total CA policies)."

    $usersResp = Get-DiscoveryUsers -Headers $headers
    if (-not $usersResp.Success) {
        throw "Could not read users: $($usersResp.Reason) -- $($usersResp.Message)"
    }
    Write-Host "  $($usersResp.Data.Count) users found."

    $groupsResp = Get-DiscoveryGroups -Headers $headers
    if (-not $groupsResp.Success) {
        throw "Could not read groups: $($groupsResp.Reason) -- $($groupsResp.Message)"
    }
    Write-Host "  $($groupsResp.Data.Count) groups found."
    Write-Host ""

    Write-Host "Opening the selection page in your browser..." -ForegroundColor Cyan
    $selection = Start-SelectionServer -Users $usersResp.Data -Groups $groupsResp.Data -ReportOnlyPolicies $reportOnlyPolicies
    Write-Host "Selection received." -ForegroundColor Green
    Write-Host ""

    $fetchGroupMembers = {
        param($groupId)
        $resp = Get-GroupMembers -Headers $headers -GroupId $groupId
        if ($resp.Success) { return $resp.Data }
        return @()
    }.GetNewClosure()

    $scopedUsers = Resolve-UserScope -Selection $selection -DiscoveredUsers $usersResp.Data -FetchGroupMembers $fetchGroupMembers
    $selectedPolicyIdSet = @{}
    foreach ($id in $selection.policy_ids) { $selectedPolicyIdSet[$id] = $true }
    $reportPolicies = @($reportOnlyPolicies | Where-Object { $selectedPolicyIdSet.ContainsKey($_.id) })

    Write-Host "Analyzing $($scopedUsers.Count) user(s) against $($reportPolicies.Count) polic$(if ($reportPolicies.Count -eq 1) { 'y' } else { 'ies' }) over the last $($selection.days) day(s)."
    Write-Host ""

    $sinceIso = (Get-Date).ToUniversalTime().AddDays(-$selection.days).ToString("yyyy-MM-ddTHH:mm:ssZ")
    $signInsByUser = @{}
    $collectionErrors = @{}

    if ($selection.all_users) {
        Write-Host "Pulling sign-in logs for all users..."
        $onPage = { param($count) Write-Host "  $count sign-ins pulled so far..." }
        $allSignInsResp = Get-SignInsAll -Headers $headers -SinceIso $sinceIso -OnPage $onPage
        if (-not $allSignInsResp.Success) {
            $reason = "$($allSignInsResp.Reason): $($allSignInsResp.Message)"
            Write-Host "  Bulk pull failed ($reason) -- every selected user will be marked not collected." -ForegroundColor Yellow
            foreach ($user in $scopedUsers) { $collectionErrors[$user.id] = $reason }
        } else {
            $upnToUserId = @{}
            foreach ($user in $scopedUsers) { $upnToUserId[$user.userPrincipalName] = $user.id }
            foreach ($signIn in $allSignInsResp.Data) {
                $userId = $upnToUserId[$signIn.userPrincipalName]
                if ($userId) {
                    if (-not $signInsByUser.ContainsKey($userId)) { $signInsByUser[$userId] = New-Object System.Collections.ArrayList }
                    [void]$signInsByUser[$userId].Add($signIn)
                }
            }
            Write-Host "  Done -- $($allSignInsResp.Data.Count) total sign-ins pulled." -ForegroundColor Green
        }
    } else {
        $userIndex = 0
        foreach ($user in $scopedUsers) {
            $userIndex++
            Write-Host "Pulling sign-ins for $($user.displayName) ($userIndex of $($scopedUsers.Count))..."
            $resp = Get-SignInsForUser -Headers $headers -UserPrincipalName $user.userPrincipalName -SinceIso $sinceIso
            if (-not $resp.Success) {
                $reason = "$($resp.Reason): $($resp.Message)"
                Write-Host "  Failed ($reason) -- marked not collected." -ForegroundColor Yellow
                $collectionErrors[$user.id] = $reason
            } else {
                $signInsByUser[$user.id] = $resp.Data
                Write-Host "  $($resp.Data.Count) sign-ins pulled." -ForegroundColor Green
            }
        }
    }
    Write-Host ""

    Write-Host "Aggregating results..."
    # PowerShell array-unwrapping gotcha (found by testing, see
    # Resolve-UserScope): keep this as a real array with 0/1/N elements.
    $signInsByUserNormalized = @{}
    foreach ($key in $signInsByUser.Keys) { $signInsByUserNormalized[$key] = @($signInsByUser[$key]) }

    $matrix = Get-UserPolicyMatrix -Users $scopedUsers -Policies $reportPolicies -SignInsByUser $signInsByUserNormalized -CollectionErrors $collectionErrors
    $totalSignIns = 0
    foreach ($key in $signInsByUserNormalized.Keys) { $totalSignIns += $signInsByUserNormalized[$key].Count }

    $meta = @{
        totalSignIns  = $totalSignIns
        requestedDays = $selection.days
    }

    $html = Get-ReportHtml -Matrix $matrix -Users $scopedUsers -Policies $reportPolicies -Meta $meta
    Write-ReportHtml -Html $html -OutputPath $OutputPath

    Write-Host "Report written to $OutputPath" -ForegroundColor Green
    if ($OpenBrowser) {
        $fullPath = (Resolve-Path $OutputPath).Path
        try { Start-Process $fullPath | Out-Null } catch {
            Write-Host "Could not open the report automatically -- open it manually: $fullPath" -ForegroundColor Yellow
        }
    }

    return $OutputPath
}

# ===========================================================================
# Entry point
#
# Guarded so this file can be dot-sourced for testing without triggering a
# real sign-in -- $MyInvocation.InvocationName distinguishes being run
# directly (or via ps2exe) from being dot-sourced with `. .\analyzer.ps1`.
# ===========================================================================

if ($MyInvocation.InvocationName -ne ".") {
    Invoke-CaReportOnlyAnalysis
}
