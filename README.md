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
2. **A selection page opens automatically** — search/multi-select users (or "all
   users"), search/select which **report-only** Conditional Access policies to
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
.\tests\test-pagination.ps1
.\tests\test-report-browser.ps1
.\tests\test-picker-browser.ps1
```

69 tests total, run against real Windows PowerShell (not mocked) — the
aggregation logic, HTML/JSON generation and escaping, the real transient HTTP
selection server's GET/POST round trip, Graph pagination (single-page and
multi-page), and two tests that actually load the generated pages into
headless Microsoft Edge and inspect the real rendered DOM rather than just
checking the JS source text: `test-report-browser.ps1` (the report) and
`test-picker-browser.ps1` (the picker — simulates real typing/clicking via
dispatched DOM events to prove selections survive a search-filter
re-render). Both skip gracefully if Edge isn't installed.

## Required permissions

Requested at sign-in via device code, against Microsoft's own first-party
"Microsoft Graph Command Line Tools" client — no app registration needed in your
tenant:

- `AuditLog.Read.All` — read sign-in logs
- `Policy.Read.All` — read Conditional Access policies
- `User.Read.All` — list users for the picker

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
- **The most severe one, caught on the very first real tenant run, not in
  testing: `Set-StrictMode -Version Latest` throws when a Graph response is
  simply missing a property, and Graph routinely omits properties instead of
  setting them null** (e.g. `@odata.nextLink` doesn't exist at all on a
  single-page response). Because `$nextUri = $resp.Data.'@odata.nextLink'`
  was a bare assignment with no try/catch around it, the throw (a
  non-terminating error under the default `$ErrorActionPreference`) meant
  `$nextUri` simply never got reassigned — the pagination `while` loop's
  condition stayed true forever and it **re-fetched the exact same Graph page
  in an unbounded loop**, printing the error every time. Fixed by dropping to
  `Set-StrictMode -Version 1.0` (still catches uninitialized-variable typos,
  but doesn't enforce property existence on dynamically-shaped external
  JSON). `tests/test-pagination.ps1` was added specifically to close this
  coverage gap — it mocks single-page (no `nextLink`) and multi-page
  responses and asserts the exact call count, with a safety-valve abort if
  more than 5 calls happen, so a regression here fails a test instead of
  hanging in front of a customer again.
- **A render function can be written correctly, added to the script, and
  still never run — because nobody added the call to it.** When the report
  was redesigned to lead with per-policy verdicts instead of the raw matrix,
  `renderHeadline()` and `renderPolicyVerdicts()` were written and correct
  but never added to the invocation list at the bottom of the `<script>`
  block. Every existing test still passed, because they only checked that
  certain strings existed in the JS *source* — none of them actually ran the
  page. This is why `tests/test-report-browser.ps1` exists: it loads the
  generated report into real headless Microsoft Edge (`msedge.exe
  --headless=new --dump-dom`) and inspects the actual rendered DOM, which is
  the only way this class of bug reliably gets caught. One more gotcha found
  building that test: piping a native process's output through PowerShell's
  `&` call operator (`& $edge ... | Out-File ...`) silently produced an empty
  capture in this environment — `Start-Process -RedirectStandardOutput`
  worked reliably where the pipe form didn't.
- **The report's visual design borrows the real GBG palette** (green
  `#4FAE7E`, red `#C81E2C`, amber `#E8954A`, blue `#4A90C8` accent, Inter
  font) from the main GBG Assessment Tool's own report CSS, rather than an
  invented palette — consistency across the tool family, not a new visual
  language per report.
- **`ConvertTo-Json` serializes a ONE-element array as a bare JSON object,
  not a one-element array — but only when that array is the TOP-LEVEL value
  handed to it.** A nested array buried inside a larger object (e.g. a
  matrix cell's `sampleEvents` list) serializes correctly regardless of its
  element count — verified directly; only the root value is affected. This
  meant the picker would throw `items is not iterable` and render nothing
  at all on any tenant with exactly one discovered user or exactly one
  report-only policy, silently working everywhere else. Found by actually
  running the picker in headless Edge against a single-user test fixture
  and reading a real thrown JS error (`window.onerror`), not by code
  review — every earlier test happened to use either zero or two-or-more
  items. `ConvertTo-ScriptSafeJson` now builds arrays by hand (serializing
  each element individually and joining with `[...]`) instead of trusting
  `ConvertTo-Json`'s own count-dependent behavior for the outer array.
- **Selections must survive a search-filter re-render, and this needs a
  real interaction test to prove, not a static one.** `renderCheckboxList`
  rebuilds every checkbox element from scratch on each keystroke in the
  search box — anything tracked only in the live DOM (a checkbox's own
  `.checked` property) is silently wiped, including items that still match
  the new filter. Selection state now lives in persistent `Set` objects
  (`selectedUserIds`/`selectedPolicyIds`) that survive every re-render,
  restored onto each checkbox as it's recreated, instead of being read back
  from the DOM. `tests/test-picker-browser.ps1` proves this by actually
  dispatching real `input`/`change` events in headless Edge (check a box,
  filter it out of view, clear the filter, assert it's still checked) —
  a bug in the earlier design, and the "Select all" / "Clear" buttons
  added alongside it, both had to be verified this way; reading the code
  is not enough evidence for interactive behavior like this.
