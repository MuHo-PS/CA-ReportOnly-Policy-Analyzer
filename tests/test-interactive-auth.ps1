# Real-execution tests for the interactive (browser + PKCE) sign-in path
# added as a fallback for tenants that block the device code flow via
# Conditional Access. Covers the pieces that don't require a live Azure AD
# tenant or a real user: PKCE challenge derivation, the loopback listener
# actually accepting a real HTTP connection, and the CA-block detection
# regex against real-shaped AADSTS error text. The full /authorize ->
# browser -> /token round trip against a live tenant is out of scope for
# an automated test (same as Get-DeviceCodeToken's live flow isn't
# automated either) -- this proves the mechanics that were newly written,
# which is exactly where new bugs would live.

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\..\analyzer.ps1"

$script:failCount = 0
$script:passCount = 0
function Check {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { $script:passCount++; Write-Host "PASS: $Name" }
    else { $script:failCount++; Write-Host "FAIL: $Name" -ForegroundColor Red }
}

# --- New-PkceChallenge: challenge must actually be derived from the verifier ---
$pkce = New-PkceChallenge
Check (-not [string]::IsNullOrEmpty($pkce.Verifier)) "PKCE verifier is generated"
Check (-not [string]::IsNullOrEmpty($pkce.Challenge)) "PKCE challenge is generated"
Check ($pkce.Verifier -ne $pkce.Challenge) "verifier and challenge are not the same value"

$sha256 = [System.Security.Cryptography.SHA256]::Create()
$expectedChallengeBytes = $sha256.ComputeHash([System.Text.Encoding]::ASCII.GetBytes($pkce.Verifier))
$expectedChallenge = [Convert]::ToBase64String($expectedChallengeBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_')
Check ($pkce.Challenge -eq $expectedChallenge) "challenge is exactly base64url(SHA-256(verifier)) -- independently recomputed and compared"

$pkce2 = New-PkceChallenge
Check ($pkce.Verifier -ne $pkce2.Verifier) "two calls produce different verifiers (not a fixed/predictable value)"

# --- Test-DeviceCodeBlockedError: real-shaped AADSTS error text ---
Check (Test-DeviceCodeBlockedError -Message "Device code sign-in failed: invalid_grant - AADSTS53003: Access has been blocked by Conditional Access policies. The access policy does not allow token issuance.") "detects a real AADSTS53003 Conditional Access block message"
Check (Test-DeviceCodeBlockedError -Message "Device code sign-in failed: invalid_grant - Access blocked by Conditional Access.") "detects the phrase 'conditional access' case-insensitively even without the exact AADSTS code"
Check (-not (Test-DeviceCodeBlockedError -Message "Device code sign-in failed: invalid_grant - AADSTS70016: Pending user authorization.")) "does NOT misfire on an unrelated AADSTS error"
Check (-not (Test-DeviceCodeBlockedError -Message "Device code sign-in timed out after 900 seconds.")) "does NOT misfire on a plain timeout message"

# --- Start-LoopbackListener + Wait-ForAuthorizationCode: a real HTTP round trip ---
$bound = Start-LoopbackListener
Check ($bound.Port -ge 8766 -and $bound.Port -le 8866) "loopback listener bound a port in the expected range"

# In-process background runspace fires a real HTTP GET at the listener,
# simulating the browser's OAuth redirect -- same pattern used in
# test-server.ps1 for the selection server, chosen there (and here) over
# Start-Job specifically to avoid separate-process remoting overhead.
function Invoke-CallbackRequest {
    param($Port, $QueryString)
    $clientScript = {
        param($Port, $QueryString)
        Start-Sleep -Milliseconds 300
        try {
            $resp = Invoke-WebRequest -Uri "http://localhost:$Port/$QueryString" -TimeoutSec 5 -UseBasicParsing -ErrorAction Stop
            return @{ ok = $true; status = $resp.StatusCode }
        } catch {
            return @{ ok = $false; error = $_.Exception.Message }
        }
    }
    $ps = [PowerShell]::Create()
    [void]$ps.AddScript($clientScript).AddArgument($Port).AddArgument($QueryString)
    return @{ PS = $ps; Handle = $ps.BeginInvoke() }
}

$realState = "test-state-abc123"
$job = Invoke-CallbackRequest -Port $bound.Port -QueryString "?code=real-auth-code-xyz&state=$realState"
$result = Wait-ForAuthorizationCode -Listener $bound.Listener -ExpectedState $realState -MaxWaitSeconds 10
[void]$job.Handle.AsyncWaitHandle.WaitOne(5000)
$job.PS.Dispose()
Check ($result.Code -eq "real-auth-code-xyz") "a real HTTP GET carrying ?code=&state= is captured as the authorization code"
Check ($null -eq $result.CallbackError) "a successful callback carries no CallbackError"
$bound.Listener.Stop()
$bound.Listener.Close()

# --- Wait-ForAuthorizationCode: a real OAuth error response ---
$bound2 = Start-LoopbackListener
$errState = "test-state-err456"
$job2 = Invoke-CallbackRequest -Port $bound2.Port -QueryString "?error=access_denied&error_description=User+cancelled&state=$errState"
$result2 = Wait-ForAuthorizationCode -Listener $bound2.Listener -ExpectedState $errState -MaxWaitSeconds 10
[void]$job2.Handle.AsyncWaitHandle.WaitOne(5000)
$job2.PS.Dispose()
Check ($null -ne $result2.CallbackError) "an ?error= callback is captured as a CallbackError, not thrown from inside the wait"
Check ($result2.CallbackError -match "access_denied") "the CallbackError carries the real error code from the query string"
$bound2.Listener.Stop()
$bound2.Listener.Close()

# --- Wait-ForAuthorizationCode: a mismatched state must not be accepted ---
# (proves the CSRF check actually rejects a spoofed/stray callback rather
# than trusting any code that shows up on the port)
$bound3 = Start-LoopbackListener
$job3 = Invoke-CallbackRequest -Port $bound3.Port -QueryString "?code=should-be-ignored&state=wrong-state"
try {
    $result3 = Wait-ForAuthorizationCode -Listener $bound3.Listener -ExpectedState "the-real-state" -MaxWaitSeconds 3
    Check $false "a mismatched-state callback should time out, not resolve (got a result instead)"
} catch {
    Check ($_.Exception.Message -match "timed out") "a mismatched-state callback is correctly ignored and the wait times out rather than accepting it"
}
[void]$job3.Handle.AsyncWaitHandle.WaitOne(5000)
$job3.PS.Dispose()
$bound3.Listener.Stop()
$bound3.Listener.Close()

Write-Host ""
Write-Host "$script:passCount passed, $script:failCount failed" -ForegroundColor $(if ($script:failCount -eq 0) { "Green" } else { "Red" })
if ($script:failCount -gt 0) { exit 1 }
