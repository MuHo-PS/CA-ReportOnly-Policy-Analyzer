<#
.SYNOPSIS
    One-command launcher for the CA Report-Only Policy Analyzer.

.DESCRIPTION
    Finds a usable Python interpreter, installs the two required packages
    (msal, requests) if they aren't already present, then runs analyzer.py.
    No venv, no manual pip steps -- just run this script.
#>

$ErrorActionPreference = "Stop"

function Find-Python {
    # Prefer the Windows "py" launcher (ships with every python.org installer),
    # then fall back to whatever "python"/"python3" resolves to on PATH.
    $candidates = @(
        @{ Cmd = "py"; Args = @("-3") },
        @{ Cmd = "python"; Args = @() },
        @{ Cmd = "python3"; Args = @() }
    )

    foreach ($candidate in $candidates) {
        $found = Get-Command $candidate.Cmd -ErrorAction SilentlyContinue
        if ($found) {
            return $candidate
        }
    }

    return $null
}

$python = Find-Python
if (-not $python) {
    Write-Error "No Python interpreter found on PATH. Install Python 3.11+ from https://python.org and try again."
    exit 1
}

$pythonDisplay = ($python.Cmd, ($python.Args -join " ") -join " ").Trim()
Write-Host "Using Python: $pythonDisplay"

# Check whether the two required packages are already importable for this
# interpreter -- skip the pip install entirely if so, since it's the slow step.
$checkArgs = $python.Args + @("-c", "import msal, requests")
& $python.Cmd @checkArgs 2>$null
$depsPresent = ($LASTEXITCODE -eq 0)

if (-not $depsPresent) {
    Write-Host "Installing required packages (msal, requests)..."
    $installArgs = $python.Args + @("-m", "pip", "install", "-r", "requirements.txt")
    & $python.Cmd @installArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Error "pip install failed -- see output above."
        exit 1
    }
} else {
    Write-Host "Required packages already installed."
}

Write-Host "Starting CA Report-Only Policy Analyzer..."
$runArgs = $python.Args + @("analyzer.py") + $args
& $python.Cmd @runArgs
exit $LASTEXITCODE
