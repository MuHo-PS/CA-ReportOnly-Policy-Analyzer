# Real-browser verification for the picker page's selection-persistence
# and Select all / Clear behavior. Loads the real generated picker.html,
# actually simulates typing/clicking via dispatched DOM events (not just a
# static one-shot dump), and reads back observable checkbox state -- the
# only way to prove selections survive a search-filter re-render, which
# bit this exact class of bug before (see README lessons-learned).
#
# Skips gracefully if Microsoft Edge isn't found.

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\..\analyzer.ps1"

$edgePaths = @(
    "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe",
    "${env:ProgramFiles}\Microsoft\Edge\Application\msedge.exe"
)
$edge = $edgePaths | Where-Object { Test-Path $_ } | Select-Object -First 1
if (-not $edge) {
    Write-Host "Microsoft Edge not found -- skipping real-browser picker verification." -ForegroundColor Yellow
    exit 0
}

$users = @([PSCustomObject]@{ id = "u1"; displayName = "Alice" })
$policies = @(
    [PSCustomObject]@{ id = "p-alpha"; displayName = "Alpha Policy" },
    [PSCustomObject]@{ id = "p-beta"; displayName = "Beta Policy" },
    [PSCustomObject]@{ id = "p-gamma"; displayName = "Gamma Policy" }
)
$pickerHtml = Get-PickerHtml -Users $users -ReportOnlyPolicies $policies

# Append a driver script that runs the actual interaction sequence and
# writes plain-text PASS/FAIL results into a div dump-dom can capture.
# Uses the page's own real DOM elements/events -- nothing about the
# picker's own script is touched or mocked.
$driver = @'
<div id="test-results" style="white-space:pre-line;"></div>
<script>
try {
(function () {
  const results = [];
  function check(name, condition) {
    results.push((condition ? "PASS" : "FAIL") + ": " + name);
  }
  function fireInput(el, value) {
    el.value = value;
    el.dispatchEvent(new Event("input", { bubbles: true }));
  }
  function fireChange(el) {
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }
  function findCheckboxByName(container, name) {
    return Array.from(container.querySelectorAll("label")).find(
      l => l.textContent.trim() === name
    ).querySelector("input");
  }

  const policyList = document.getElementById("policy-list");
  const policySearch = document.getElementById("policy-search");

  // 1) Check Alpha, then filter down to only Beta, then clear the filter --
  //    Alpha must still be checked after coming back into view.
  let alphaCb = findCheckboxByName(policyList, "Alpha Policy");
  alphaCb.checked = true;
  fireChange(alphaCb);

  fireInput(policySearch, "beta");
  check("filtering to 'beta' hides Alpha and Gamma", policyList.querySelectorAll("label").length === 1);

  fireInput(policySearch, "");
  alphaCb = findCheckboxByName(policyList, "Alpha Policy");
  check("Alpha stays checked after being filtered out and back in", alphaCb.checked === true);

  // 2) Select all while filtered to a subset only checks that subset.
  fireInput(policySearch, "gamma");
  document.getElementById("policy-select-all").click();
  fireInput(policySearch, "");
  const betaCb = findCheckboxByName(policyList, "Beta Policy");
  const gammaCb = findCheckboxByName(policyList, "Gamma Policy");
  check("Select-all-while-filtered only selects the filtered (Gamma) item", gammaCb.checked === true && betaCb.checked === false);
  check("Select-all-while-filtered does not affect Alpha's earlier selection", findCheckboxByName(policyList, "Alpha Policy").checked === true);

  // 3) Clear while filtered only clears the filtered subset.
  fireInput(policySearch, "alpha");
  document.getElementById("policy-clear").click();
  fireInput(policySearch, "");
  check("Clear-while-filtered only clears the filtered (Alpha) item", findCheckboxByName(policyList, "Alpha Policy").checked === false);
  check("Clear-while-filtered does not affect Gamma's earlier selection", findCheckboxByName(policyList, "Gamma Policy").checked === true);

  document.getElementById("test-results").textContent = results.join("\n");
})();
} catch (e) {
  document.getElementById("test-results").textContent = "DRIVER THREW: " + e.message + "\n" + e.stack;
}
</script>
'@

$testHtml = $pickerHtml.Replace("</body>", "$driver</body>")
$tmpHtml = [System.IO.Path]::GetTempFileName() + ".html"
Write-ReportHtml -Html $testHtml -OutputPath $tmpHtml

$tmpDump = [System.IO.Path]::GetTempFileName()
$tmpErr = [System.IO.Path]::GetTempFileName()
$fileUri = "file:///" + ($tmpHtml -replace '\\', '/')
Start-Process -FilePath $edge -ArgumentList @("--headless=new", "--disable-gpu", "--dump-dom", $fileUri) `
    -RedirectStandardOutput $tmpDump -RedirectStandardError $tmpErr -NoNewWindow -Wait

$dom = Get-Content -Path $tmpDump -Raw -ErrorAction SilentlyContinue
if ($null -eq $dom) { $dom = "" }

$resultsMatch = [regex]::Match($dom, '(?s)<div id="test-results"[^>]*>(.*?)</div>')
$failCount = 0
if (-not $resultsMatch.Success -or [string]::IsNullOrWhiteSpace($resultsMatch.Groups[1].Value)) {
    Write-Host "FAIL: could not find any test-results output in the rendered DOM (driver script may have thrown)" -ForegroundColor Red
    $failCount = 1
} else {
    $lines = $resultsMatch.Groups[1].Value -split "`n" | Where-Object { $_.Trim() -ne "" }
    foreach ($line in $lines) {
        $trimmed = $line.Trim()
        if ($trimmed.StartsWith("PASS")) { Write-Host $trimmed -ForegroundColor Green }
        else { Write-Host $trimmed -ForegroundColor Red; $failCount++ }
    }
    if ($lines.Count -eq 0) { Write-Host "FAIL: results div was empty" -ForegroundColor Red; $failCount++ }
}

Remove-Item $tmpHtml, $tmpDump, $tmpErr -Force -ErrorAction SilentlyContinue

Write-Host ""
if ($failCount -eq 0) { Write-Host "ALL PICKER SELECTION-PERSISTENCE TESTS PASSED" -ForegroundColor Green }
else { Write-Host "$failCount PICKER SELECTION-PERSISTENCE TESTS FAILED" -ForegroundColor Red; exit 1 }
