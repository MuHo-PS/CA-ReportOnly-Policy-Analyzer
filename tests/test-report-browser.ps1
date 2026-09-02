# Real-browser DOM verification for Get-ReportHtml's JS -- catches bugs
# string-presence checks cannot, most importantly: a render function that
# exists and is correct but was never actually CALLED at the bottom of the
# script (exactly what happened during development -- renderHeadline() and
# renderPolicyVerdicts() were written, correct, and simply never invoked;
# every prior test still passed because they only checked the JS *source*
# contained the right substrings, not that a real browser executing it
# produced the right DOM).
#
# Skips gracefully (does not fail) if Microsoft Edge isn't found, so this
# stays optional on environments without it.

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\..\analyzer.ps1"

$edgePaths = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"
)
$edge = $edgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $edge) {
    Write-Host "Microsoft Edge not found -- skipping real-browser report verification." -ForegroundColor Yellow
    exit 0
}

# Synthetic fixture covering all four verdicts in one report:
# would-affect, ready, no-signal, and unknown-result-type.
$users = @(
    [PSCustomObject]@{ id = "u1"; displayName = "Alice"; userPrincipalName = "alice@contoso.com" }
)
$policies = @(
    [PSCustomObject]@{ id = "p-affect"; displayName = "Policy With Real Impact" },
    [PSCustomObject]@{ id = "p-ready"; displayName = "Policy Ready To Enforce" },
    [PSCustomObject]@{ id = "p-none"; displayName = "Policy With No Signal" },
    [PSCustomObject]@{ id = "p-unknown"; displayName = "Policy With Unrecognized Result" }
)
$matrix = @{
    u1 = @{
        "p-affect"  = @{
            notCollected = $false
            counts = @{ reportOnlyFailure = 2; reportOnlyNotApplied = 3 }
            notEvaluatedCount = 0
            totalSignIns = 5
            sampleEvents = @(
                @{ timestamp = "2026-08-01T09:00:00Z"; app = "Office 365"; location = "Cairo, EG"; deviceCompliant = $false; resultBucket = "reportOnlyFailure" },
                @{ timestamp = "2026-08-02T09:00:00Z"; app = "Office 365"; location = "Giza, EG"; deviceCompliant = $true; resultBucket = "reportOnlyFailure" }
            )
            dailyCounts = @{
                "2026-08-01" = @{ reportOnlyFailure = 1; reportOnlyNotApplied = 2 }
                "2026-08-02" = @{ reportOnlyFailure = 1; reportOnlyNotApplied = 1 }
            }
        }
        "p-ready"   = @{ notCollected = $false; counts = @{ reportOnlySuccess = 4 }; notEvaluatedCount = 1; totalSignIns = 5; sampleEvents = @(); dailyCounts = @{} }
        "p-none"    = @{ notCollected = $false; counts = @{}; notEvaluatedCount = 5; totalSignIns = 5; sampleEvents = @(); dailyCounts = @{} }
        "p-unknown" = @{ notCollected = $false; counts = @{ unknownFutureValue = 1 }; notEvaluatedCount = 4; totalSignIns = 5; sampleEvents = @(); dailyCounts = @{} }
    }
}
$meta = @{ totalSignIns = 20; requestedDays = 7 }

$html = Get-ReportHtml -Matrix $matrix -Users $users -Policies $policies -Meta $meta
$tmpHtml = [System.IO.Path]::GetTempFileName() + ".html"
Write-ReportHtml -Html $html -OutputPath $tmpHtml

$tmpDump = [System.IO.Path]::GetTempFileName()
$tmpErr = [System.IO.Path]::GetTempFileName()
$fileUri = "file:///" + ($tmpHtml -replace '\\', '/')
# Start-Process with explicit redirection, not `&` + pipe -- more reliable
# for capturing a native GUI-adjacent process's output than piping through
# PowerShell's call operator in this environment (found by testing: the
# pipe form silently produced an empty capture here).
Start-Process -FilePath $edge -ArgumentList @("--headless=new", "--disable-gpu", "--dump-dom", $fileUri) `
    -RedirectStandardOutput $tmpDump -RedirectStandardError $tmpErr -NoNewWindow -Wait

$dom = Get-Content -Path $tmpDump -Raw -ErrorAction SilentlyContinue
if ($null -eq $dom) { $dom = "" }

# Strip the <script> block's own source text before inspecting -- dump-dom
# includes it verbatim, and it legitimately contains these class names and
# label strings as JS source, which would otherwise produce false passes.
$domWithoutScript = $dom -replace '(?s)<script.*?</script>', ''

$failCount = 0
function Check {
    param([bool]$Condition, [string]$Name)
    if ($Condition) { Write-Host "PASS: $Name" }
    else { Write-Host "FAIL: $Name" -ForegroundColor Red; $script:failCount++ }
}

Check ($domWithoutScript -match 'class="headline"[^>]*>\s*<strong>1</strong> of 4') "headline correctly counts exactly 1 would-affect policy"
Check ($domWithoutScript -match 'verdict-affect[\s\S]{0,120}Policy With Real Impact|Policy With Real Impact[\s\S]{0,120}verdict-affect') "the impacted policy renders with the affect badge"
Check ($domWithoutScript -match 'verdict-ready[\s\S]{0,120}Policy Ready To Enforce|Policy Ready To Enforce[\s\S]{0,120}verdict-ready') "the zero-impact policy renders with the ready badge"
Check ($domWithoutScript -match 'verdict-none[\s\S]{0,120}Policy With No Signal|Policy With No Signal[\s\S]{0,120}verdict-none') "the no-signal policy renders with the none badge"
Check ($domWithoutScript -match 'verdict-unknown[\s\S]{0,120}Policy With Unrecognized Result|Policy With Unrecognized Result[\s\S]{0,120}verdict-unknown') "the unknown-result policy renders with the unknown badge"
Check ($domWithoutScript -notmatch [regex]::Escape('${escapeHtml')) "no unevaluated JS template literal leaked into the rendered DOM"

# --- New charts: donut summary, segmented bars, timeline, impact breakdown ---
Check ($domWithoutScript -match '<svg[^>]*class="donut-svg"') "the verdict summary donut chart actually rendered as a real SVG element"
Check ($domWithoutScript -match 'donut-total">4<') "the donut's center total correctly shows all 4 policies"
Check (([regex]::Matches($domWithoutScript, 'class="segment"')).Count -ge 4) "segmented bars rendered with real colored segments (at least one per non-zero bucket, across cards)"
Check ($domWithoutScript -match 'timeline-chart') "a daily impact timeline rendered for the policy with real dailyCounts data"
Check ($domWithoutScript -match '2026-08-01 to 2026-08-02') "the timeline's date range label reflects the real min/max dates in dailyCounts"
Check ($domWithoutScript -match 'Device compliance: 1 compliant, 1 non-compliant, 0 unknown') "the impact breakdown correctly tallies real sample-event device compliance"
Check ($domWithoutScript -match 'Cairo, EG \(1\)' -and $domWithoutScript -match 'Giza, EG \(1\)') "the impact breakdown's top-locations list reflects the real sample events"
# The no-signal and ready policies have empty dailyCounts -- their cards
# must not render an empty/broken timeline chart at all.
$noSignalCardMatch = [regex]::Match($domWithoutScript, '(?s)Policy With No Signal.*?(?=verdict-card"|$)')
Check (-not $noSignalCardMatch.Value.Contains('timeline-chart')) "a policy with empty dailyCounts renders no timeline chart, not a broken empty one"

Remove-Item $tmpHtml, $tmpDump -Force -ErrorAction SilentlyContinue

Write-Host ""
if ($script:failCount -eq 0) { Write-Host "ALL REAL-BROWSER REPORT TESTS PASSED" -ForegroundColor Green }
else { Write-Host "$($script:failCount) REAL-BROWSER REPORT TESTS FAILED" -ForegroundColor Red; exit 1 }
