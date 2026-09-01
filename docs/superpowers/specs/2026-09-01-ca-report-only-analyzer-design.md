# CA Report-Only Policy Analyzer — Design Spec

Date: 2026-09-01
Status: Approved for implementation planning

## Purpose

A standalone tool that answers a question the Entra portal doesn't answer directly:
**for a given set of users over a given time window, which Conditional Access policies
currently running in report-only mode would actually have applied — and to what
effect — had they been enforced?**

It works by pulling real Entra ID sign-in log events, reading each event's own
`appliedConditionalAccessPolicies[]` record (Microsoft's own evaluation result for that
policy against that sign-in), and aggregating those results per user × per policy. It
does not infer or simulate anything — every number in the output traces back to a real,
already-evaluated Graph API result.

This is a different capability from static CA-policy analyzers (e.g. the reviewed
`Jhope188/ca-policy-analyzer` project) which check policy *configuration* against best
practices/CIS/personas. Those never look at sign-in telemetry. This tool never looks at
policy configuration for best-practice scoring — it only measures observed behavior.

## Non-goals (v1)

- Not a CA policy best-practice/configuration analyzer (see above).
- Not a live dashboard — one run produces one static report artifact.
- Not applicable to workload-identity / service-principal sign-ins (`/auditLogs/signIns`
  only, not the service-principal sign-in variant) — different data shape, deferred.
- No write access of any kind — pure read/report tool, never touches CA policy state.
- No attempt to reconstruct historical policy-mode changes — Graph only exposes the
  *current* policy list; the report explicitly states this limitation (see Honesty
  Rules below) rather than pretending otherwise.

## Architecture

Single Python process, three sequential phases, no persistent service:

```
┌─────────────┐     ┌───────────────────────┐     ┌────────────────────────┐
│ Phase A      │     │ Phase B                │     │ Phase C                │
│ Auth +       │ --> │ Scoping                │ --> │ Collection + Report    │
│ Discovery    │     │ (transient local       │     │                        │
│              │     │  HTTP server + browser)│     │                        │
└─────────────┘     └───────────────────────┘     └────────────────────────┘
```

### Phase A — Auth + Discovery

- MSAL device-code flow against Microsoft's first-party public client
  `14d82eec-204b-4c2f-b7e8-296a70dab67e` ("Microsoft Graph Command Line Tools" /
  "Microsoft Graph PowerShell") — same mechanism the existing GBG Assessment Tool
  uses. **No app registration required**, works against any tenant the signed-in user
  has rights in.
- Scopes requested: `AuditLog.Read.All`, `Policy.Read.All`, `User.Read.All`,
  `Group.Read.All`, `offline_access`.
- After sign-in, fetch (all paginated via `@odata.nextLink`):
  - `GET /v1.0/identity/conditionalAccess/policies` — id, displayName, state
    (`enabled` / `enabledForReportingButNotEnforced` / `disabled`).
  - `GET /v1.0/users?$select=id,displayName,userPrincipalName` — full user list.
  - `GET /v1.0/groups?$select=id,displayName` — full group list.
- Disabled CA policies are dropped from the picker entirely (nothing to evaluate).
  Enabled and report-only policies are both shown, visually distinguished — enabled
  ones are included for context only, report-only ones are the actual analysis subject.

### Phase B — Scoping (transient local server)

- A loopback-only HTTP server (`127.0.0.1`, OS-assigned free port) serves one page:
  the discovered users/groups/policies embedded as JSON, rendered as searchable
  multi-select dropdowns (client-side filtering, no server round-trip per keystroke).
- Controls: user scope (All users / search+select specific users / search+select
  specific groups — mixing individual users and groups in one run is allowed), day
  range (numeric input, no hard cap, but a warning renders if it exceeds typical
  Entra ID sign-in log retention of 30 days since results beyond retention will come
  back empty), and policy scope (multi-select over report-only + enabled policies).
- The browser opens automatically (`webbrowser.open`) once the server is up.
- On submit, the page POSTs the selection JSON to the same server; the server stores
  it, responds 200, and shuts itself down. The main script was blocked waiting on this
  and now proceeds to Phase C.
- No auth happens on this server and it accepts no external traffic — it exists only
  to render/collect the selection UI locally.

### Phase C — Collection + Report

- Resolve the selection to a concrete user set: "All" → the full discovery list;
  specific users → as selected; groups → `GET /v1.0/groups/{id}/members` (paginated),
  unioned and deduplicated with any individually selected users.
- Pull sign-in logs: `GET /v1.0/auditLogs/signIns` filtered by `createdDateTime ge
  <isoDate>`, paginated via `@odata.nextLink`. For "all users" scope, one filtered
  pull by date only. For a bounded user set, one filtered-by-UPN pull per user
  (bounded sets are expected to be small enough that per-user calls are more
  reliable than fighting Graph's `$filter` OR/URL-length limits).
- Respect `Retry-After` on HTTP 429; otherwise exponential backoff with a capped
  retry count per request. Progress is printed to the terminal (`N sign-ins pulled
  so far...`) since a full-tenant 30-day pull can take a while.
- Aggregate per (user, policy) pair (see Data Model below).
- Render one self-contained HTML report from a template, embedding the aggregated
  JSON, and open it in the browser.

## Data Model — three-state honesty, never collapsed

For every (user, selected-policy) pair, track four distinct buckets. These must never
be collapsed into each other — this project's own house lesson (see the GBG Assessment
Tool's repeated "silent-wrong-data" incidents) is that collapsing "we didn't observe
this" into "this didn't happen" produces a false conclusion baked into a number.

1. **Evaluated** — the sign-in's `appliedConditionalAccessPolicies[]` array contains an
   entry for this policy id. Bucketed by its literal `result` value:
   `reportOnlySuccess`, `reportOnlyFailure`, `reportOnlyNotApplied`,
   `reportOnlyInterrupted` for report-only policies; `success`, `failure`,
   `notApplied`, `notEnabled` for enabled policies shown for context.
   `unknownFutureValue` is kept as its own labeled bucket, never dropped or merged.
2. **Not evaluated** — no entry for this policy exists on that sign-in at all. This
   means CA did not run this policy against this specific request (could predate the
   policy's creation, or the sign-in's resource/flow was out of the policy's scope
   entirely). **This is never rendered as "would not apply"** — it is its own state.
3. **Not collected** — the sign-in pull for that user/range failed outright (403,
   exhausted retries, etc.). Rendered as unknown, never as a zero, and the report
   names the specific reason.
4. **Sample events** — up to 50 raw sign-in records per (user, policy) cell, each with
   timestamp, application, location, device compliance, and the raw result string —
   enough for a human to open a cell and verify the aggregate themselves rather than
   trusting a number blindly.

**Standing caveat printed in the report itself:** Graph exposes only the *current* CA
policy list; if a policy's mode (report-only vs enforced) changed at any point during
the analyzed window, this tool cannot detect that and the results assume the mode was
constant for the whole period. This is stated explicitly, not left implicit.

## Report Output

One static, self-contained HTML file (no external CDN dependency, matching the existing
ISO console / Zero Trust board precedent in this workspace) containing:

1. **Summary cards** — total sign-ins pulled, user count, report-only policies
   analyzed, date range actually covered (vs requested, if retention truncated it),
   and top-line would-apply rate per policy.
2. **User × policy matrix** — rows = selected users, columns = selected policies, each
   cell colored by dominant result state and showing its count; click to expand the
   sample-events drill-down for that cell.
3. **Per-policy bar chart** — result distribution (would-apply / would-not-apply /
   interrupted / not evaluated) aggregated across all selected users, for an at-a-glance
   "is this ready to enforce" read.
4. **Client-side re-filtering** — the embedded dataset can be re-sliced (e.g. by result
   type) without re-running the collection.
5. A visible caveats section: the current-policy-list-only limitation above, the
   interactive-sign-ins-only scope boundary, and the requested-vs-actual date range.

Charts are hand-written vanilla JS/SVG against the embedded JSON — no external chart
library dependency, consistent with prior tools in this workspace.

## Error Handling

| Condition | Behavior |
|---|---|
| HTTP 429 from Graph | Respect `Retry-After`; otherwise capped exponential backoff |
| 403 / insufficient scope on a call | Abort that specific data source cleanly; mark affected users/policies "not collected" with the real reason, never a fabricated zero |
| Token expiring mid-pull | MSAL's token cache handles silent refresh before each batch |
| Selected group has zero members | Rendered explicitly ("0 users in this group"), not silently skipped |
| Zero report-only policies selected/exist | Report states this plainly, does not render an empty chart implying zero risk |
| Requested day range exceeds actual log retention | Report shows the actual covered range distinctly from the requested one |

## File Layout

```
ca-report-only-analyzer/
├── analyzer.py              # entry point: orchestrates phases A/B/C
├── graph_client.py          # auth (MSAL device code) + paginated Graph calls + backoff
├── aggregate.py             # pure function(s): raw sign-in JSON -> matrix data model
├── templates/
│   ├── picker.html          # Phase B selection page template
│   └── report.html          # Phase C output report template
├── requirements.txt         # msal
├── README.md                # usage, required consent, limitations
└── docs/superpowers/specs/  # this spec
```

## Testing Strategy

No live tenant or browser is available in the current dev sandbox (same constraint
documented in the existing GBG Assessment Tool's CLAUDE.md). Verification split
accordingly:

- **Unit-testable now**: `aggregate.py`'s pure aggregation function, driven by
  synthetic sign-in JSON fixtures covering every result bucket (including
  `unknownFutureValue`, missing-entry "not evaluated" cases, and mixed results across
  multiple sign-ins for the same user/policy pair).
- **Unit-testable now**: `graph_client.py`'s pagination and 429/backoff logic, against
  a mocked HTTP layer (no real Graph calls).
- **Explicitly NOT verifiable here, flagged as such in any implementation report**:
  the real device-code sign-in flow, the picker page rendered in an actual browser,
  the transient server's browser round-trip, and any real tenant's sign-in data.

## Open Items Deferred Past v1

- Workload-identity / service-principal sign-in analysis (different data shape).
- Any write path (e.g. "promote this report-only policy to enforced" action) —
  explicitly out of scope; this tool only reads and reports.
