# CA Report-Only Policy Analyzer

A standalone tool that answers: for a chosen set of users over a chosen time window,
which Entra ID Conditional Access policies currently in **report-only** mode would
actually have applied — and to what effect?

It reads real sign-in log events and their own `appliedConditionalAccessPolicies[]`
evaluation results — it never infers or simulates a policy's behavior.

Rebuilt in native PowerShell (no Python, no runtime dependencies) so it runs
on any Windows machine with nothing to install.

## Usage

**Easiest — run the compiled `.exe`** (built via `build.ps1`, see below):

```
.\CA-ReportOnly-Policy-Analyzer.exe
```

**Or run the script directly** — every Windows machine already has the PowerShell
needed:

```powershell
.\analyzer.ps1
```

Either way:

1. **Device-code sign-in** — prints a URL + short code. Go to
   `https://login.microsoft.com/device` in any browser (even your phone), enter
   the code, sign in with an account that has read rights in the tenant you want
   to analyze.
2. **A selection page opens automatically** — search/multi-select users or groups
   (or "all users"), pick which **report-only** Conditional Access policies to
   analyze (only report-only ones are ever shown — this tool measures what they
   would have done, not enforced policies), set the day range, click Generate.
3. **Progress prints to the terminal** while sign-in logs are pulled — this can
   take a while on a large tenant/wide date range; the terminal window is how you
   know it's working, not frozen.
4. **The report opens automatically** as `ca-report-only-analysis.html`.

## Building the .exe

```powershell
.\build.ps1
```

Installs the `ps2exe` module if needed and compiles `analyzer.ps1` into
`ca-report-only-analyzer.exe`. Run this with `powershell.exe` (Windows
PowerShell 5.1), not `pwsh.exe`, so the compiled binary targets the engine
every Windows machine has built in by default.

## Running the tests

```powershell
.\tests\test-aggregate.ps1
.\tests\test-html.ps1
.\tests\test-server.ps1
```

45 tests total, run against real Windows PowerShell (not mocked) — the
aggregation logic, HTML/JSON generation and escaping, and the real transient
HTTP selection server's GET/POST round trip.

## Required permissions

Requested at sign-in via device code, against Microsoft's own first-party
"Microsoft Graph Command Line Tools" client — no app registration needed in your
tenant:

- `AuditLog.Read.All` — read sign-in logs
- `Policy.Read.All` — read Conditional Access policies
- `User.Read.All` — list users for the picker
- `Group.Read.All` — list groups and resolve group membership for the picker

This tool is read-only. It never writes, creates, or modifies anything in your tenant.

## Limitations

- Graph exposes only the *current* CA policy list, not its history — if a policy's
  mode changed during the analyzed window, this tool can't detect that; results
  assume the mode was constant for the whole period.
- Interactive user sign-ins only. Workload-identity/service-principal sign-ins use a
  different Graph endpoint and are not included in v1.
- Entra ID sign-in log retention is typically 30 days; requesting a longer window
  may return less data than requested.
- A missing policy entry on a sign-in event means Conditional Access did not
  evaluate that policy for that specific request (its conditions — app, resource,
  risk level, scope — didn't match) — shown as "not evaluated," which is never the
  same thing as "would not apply to this user in general," and is not evidence
  anything is broken.

## Why this was rebuilt from an earlier Python version

The first version (Python + a PowerShell launcher wrapper) hit real problems on
its first live run: the picker page showed all non-disabled CA policies instead
of only report-only ones, the sign-in pull had no progress output so a real
(slow) pull looked identical to a frozen process, and the launcher script itself
carried two real Windows-PowerShell-specific bugs (non-ASCII characters breaking
the parser under the system codepage, and `$ErrorActionPreference = "Stop"`
turning routine native-command stderr into script-terminating errors). Rather
than patch a Python tool wrapped for PowerShell users, it was rebuilt as native
PowerShell — no interpreter/dependency story at all on a Windows machine — and,
this time, actually executed against a real Windows PowerShell 5.1 engine
throughout development (via WSL interop to the host's real `powershell.exe`)
instead of being written and shipped untested.

**Real bugs this caught before anyone hit them, worth knowing if you touch this
codebase:**

- **A function returning a bare array with exactly one element gets silently
  unwrapped to a scalar on return.** Any function whose job is "return a
  collection" uses the unary comma operator (`return , @($result)`) to force
  the caller to always receive a real array regardless of element count.
- **`ConvertTo-Json` on an empty array returns `$null`, not the string `"[]"`.**
  `ConvertTo-ScriptSafeJson` special-cases this — otherwise any list that
  happens to be empty (zero groups, zero policies) would embed literal `null`
  into an embedded `<script>` block instead of an iterable empty array.
- **PowerShell's interpolating here-strings (`@" ... "@`) treat `${...}` as
  their own variable-interpolation syntax** — which collides head-on with
  JavaScript's `${...}` template-literal syntax used throughout this tool's
  embedded HTML/JS. Both `Get-PickerHtml` and `Get-ReportHtml` use
  non-interpolating (`@' ... '@`) here-strings with `__PLACEHOLDER__` tokens
  substituted via `.Replace()` instead, specifically to avoid this.
- **Windows PowerShell 5.1's `Invoke-WebRequest`, without `-UseBasicParsing`,
  can throw an interactive confirmation prompt** ("Script code in the web page
  might be run...") the first time it's used in a session, because it tries to
  use Internet Explorer's DOM engine. In any non-interactive context (or on a
  machine where IE's first-run hasn't been dismissed) that prompt cannot be
  answered and the call hangs/fails. Every `Invoke-WebRequest` call in this
  codebase passes `-UseBasicParsing`.
- **`System.Net.HttpListener`'s async `BeginGetContext` must be called exactly
  once per connection actually accepted**, then polled via `WaitOne` on that
  *same* `IAsyncResult` until it completes. Calling `BeginGetContext` again on
  every poll tick (discarding the previous pending result) silently breaks the
  listener's internal accept state and connections stop arriving.
- **Windows PowerShell's `ConvertTo-Json` already Unicode-escapes angle
  brackets in string values** (each `<` and `>` comes out as a six-character
  backslash-u escape sequence, not the raw character) — a stronger, built-in
  safety net against script-tag injection than Python's `json.dumps` provides
  (which needed a manual text-replace fix in the earlier version). Kept the
  manual `</script>` replace in `ConvertTo-ScriptSafeJson` anyway as
  defense-in-depth, but it's redundant given this native behavior.
