# CA Report-Only Policy Analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a standalone Python tool that pulls Entra ID sign-in logs, reads each
event's `appliedConditionalAccessPolicies[]` result, and produces a self-contained HTML
report showing which report-only CA policies would have applied to which users.

**Architecture:** Three sequential phases in one process — (A) MSAL device-code auth +
Graph discovery of policies/users/groups, (B) a transient loopback HTTP server serving a
browser-based picker page that returns the user's scope selection, (C) paginated
sign-in-log collection, pure-function aggregation into a three-state (evaluated / not
evaluated / not collected) data model, and a static HTML report renderer. Business logic
(aggregation, scope resolution) is kept in pure functions separate from I/O (HTTP calls,
the server, file writes) so it can be unit-tested without a live tenant.

**Tech Stack:** Python 3.11+, `msal` (device-code OAuth2 + brings `requests`
transitively), `requests` (direct Graph calls), stdlib `http.server` (transient picker
server), stdlib `webbrowser`, pytest (tests only). No frontend build step — `picker.html`
and `report.html` are hand-written vanilla HTML/CSS/JS templates with placeholder tokens
filled in by Python string substitution.

**Spec:** `docs/superpowers/specs/2026-09-01-ca-report-only-analyzer-design.md`

## Global Constraints

- No live Entra tenant or browser is available in the dev sandbox this plan is executed
  in. Every task's tests must be runnable with **mocked** HTTP/MSAL/browser calls —
  never assume a real Graph endpoint or real device-code prompt is reachable. Any claim
  of "verified" in a task's completion note must say *what* was verified (unit test
  against a fixture) and *not* imply live-tenant verification.
- Auth uses the first-party public client id `14d82eec-204b-4c2f-b7e8-296a70dab67e`
  ("Microsoft Graph Command Line Tools") — never invent or register a different client
  id.
- Scopes requested: `AuditLog.Read.All`, `Policy.Read.All`, `User.Read.All`,
  `Group.Read.All`. (`offline_access` is handled automatically by MSAL for public
  clients and is not passed explicitly — passing it manually triggers an MSAL warning.)
- The three-state data model (**evaluated** / **not evaluated** / **not collected**)
  must never be collapsed into two states anywhere in the aggregation or rendering
  code. A missing `appliedConditionalAccessPolicies[]` entry is *not evaluated*, never
  *would not apply*. A failed collection is *not collected*, never a zero.
- `unknownFutureValue` (or any result string outside the known Graph enum) is kept as
  its own labeled bucket — never dropped, never merged into an existing bucket.
- No write operations anywhere — this tool only reads Graph data and writes its own
  local report file. Never call a write/PATCH/POST Graph endpoint other than the
  transient picker server's own `/submit`.
- No external CDN / JS library dependency in `picker.html` or `report.html` — all
  chart/matrix rendering is hand-written vanilla JS/SVG, consistent with the spec.

---

## File Structure

```
ca-report-only-analyzer/
├── aggregate.py             # Task 1-3: pure aggregation, no I/O
├── graph_client.py          # Task 4-6: MSAL auth + paginated Graph calls + backoff
├── pipeline.py              # Task 7: pure scope-resolution logic (groups -> members)
├── selection_server.py      # Task 8: transient loopback HTTP server
├── report_renderer.py       # Task 9: static HTML report generation
├── analyzer.py              # Task 10: CLI entry point, wires everything together
├── templates/
│   ├── picker.html          # Task 8: selection page template
│   └── report.html          # Task 9: report page template
├── requirements.txt         # Task 1: msal, requests
├── requirements-dev.txt     # Task 1: pytest
├── README.md                # Task 10: usage, consent scopes, limitations
├── .gitignore                # Task 1
└── tests/
    ├── test_aggregate.py     # Task 1-3
    ├── test_graph_client.py  # Task 4-6
    ├── test_pipeline.py      # Task 7
    ├── test_selection_server.py  # Task 8
    ├── test_report_renderer.py   # Task 9
    └── test_analyzer.py      # Task 10
```

---

### Task 1: Project scaffolding + result classification

**Files:**
- Create: `requirements.txt`
- Create: `requirements-dev.txt`
- Create: `.gitignore`
- Create: `aggregate.py`
- Test: `tests/test_aggregate.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `aggregate.KNOWN_RESULTS: frozenset[str]`, `aggregate.classify_result(raw_result: str) -> str`

- [ ] **Step 1: Create project scaffolding files**

`requirements.txt`:
```
msal>=1.28.0
requests>=2.31.0
```

`requirements-dev.txt`:
```
-r requirements.txt
pytest>=8.0.0
```

`.gitignore`:
```
__pycache__/
*.pyc
.venv/
venv/
*.egg-info/
ca-report-only-*.html
.pytest_cache/
```

- [ ] **Step 2: Write the failing test for result classification**

```python
# tests/test_aggregate.py
from aggregate import classify_result, KNOWN_RESULTS


def test_known_report_only_results_pass_through():
    for value in (
        "reportOnlySuccess",
        "reportOnlyFailure",
        "reportOnlyNotApplied",
        "reportOnlyInterrupted",
        "success",
        "failure",
        "notApplied",
        "notEnabled",
    ):
        assert classify_result(value) == value


def test_unrecognized_result_maps_to_unknown_future_value():
    assert classify_result("somethingGraphAddsLater") == "unknownFutureValue"


def test_known_results_constant_matches_expected_set():
    assert KNOWN_RESULTS == frozenset({
        "reportOnlySuccess", "reportOnlyFailure",
        "reportOnlyNotApplied", "reportOnlyInterrupted",
        "success", "failure", "notApplied", "notEnabled",
    })
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_aggregate.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'aggregate'`

- [ ] **Step 4: Write minimal implementation**

```python
# aggregate.py
"""Pure aggregation logic for CA report-only sign-in analysis.

No network I/O lives in this module. Every function here takes plain
dicts/lists already fetched by graph_client.py and returns plain
dicts/lists — this keeps the three-state honesty rules (evaluated /
not evaluated / not collected) testable without a live tenant.
"""

KNOWN_RESULTS = frozenset({
    "reportOnlySuccess", "reportOnlyFailure",
    "reportOnlyNotApplied", "reportOnlyInterrupted",
    "success", "failure", "notApplied", "notEnabled",
})


def classify_result(raw_result: str) -> str:
    """Map a raw Graph appliedConditionalAccessPolicies result string to a
    known bucket, or 'unknownFutureValue' if Graph has added a new one we
    don't recognize yet. Never drop or silently merge an unrecognized value.
    """
    return raw_result if raw_result in KNOWN_RESULTS else "unknownFutureValue"
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_aggregate.py -v`
Expected: PASS (3 passed)

- [ ] **Step 6: Commit**

```bash
git add requirements.txt requirements-dev.txt .gitignore aggregate.py tests/test_aggregate.py
git commit -m "Add project scaffolding and result classification"
```

---

### Task 2: Per-cell aggregation (evaluated / not-evaluated / sample events)

**Files:**
- Modify: `aggregate.py`
- Test: `tests/test_aggregate.py`

**Interfaces:**
- Consumes: `classify_result` (Task 1)
- Produces: `aggregate.extract_applied_policy_entry(signin: dict, policy_id: str) -> dict | None`,
  `aggregate.aggregate_cell(sign_ins: list[dict], policy_id: str, max_samples: int = 50) -> dict`
  returning `{"not_collected": False, "counts": dict[str, int], "not_evaluated_count": int, "total_signins": int, "sample_events": list[dict]}`.
  Each `sample_events` item is `{"timestamp": str, "app": str, "location": str, "device_compliant": bool | None, "result_bucket": str}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_aggregate.py (append)
from aggregate import extract_applied_policy_entry, aggregate_cell


def _signin(policies=None, created="2026-08-01T10:00:00Z", app="Office 365",
            city="Cairo", country="EG", compliant=None):
    return {
        "createdDateTime": created,
        "appDisplayName": app,
        "location": {"city": city, "countryOrRegion": country},
        "deviceDetail": {"isCompliant": compliant},
        "appliedConditionalAccessPolicies": policies or [],
    }


def test_extract_applied_policy_entry_finds_matching_id():
    signin = _signin(policies=[
        {"id": "policy-a", "result": "reportOnlySuccess"},
        {"id": "policy-b", "result": "notApplied"},
    ])
    entry = extract_applied_policy_entry(signin, "policy-b")
    assert entry == {"id": "policy-b", "result": "notApplied"}


def test_extract_applied_policy_entry_returns_none_when_absent():
    signin = _signin(policies=[{"id": "policy-a", "result": "success"}])
    assert extract_applied_policy_entry(signin, "policy-z") is None


def test_aggregate_cell_buckets_evaluated_results():
    sign_ins = [
        _signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}]),
        _signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}]),
        _signin(policies=[{"id": "p1", "result": "reportOnlyFailure"}]),
    ]
    cell = aggregate_cell(sign_ins, "p1")
    assert cell["not_collected"] is False
    assert cell["counts"] == {"reportOnlySuccess": 2, "reportOnlyFailure": 1}
    assert cell["not_evaluated_count"] == 0
    assert cell["total_signins"] == 3


def test_aggregate_cell_counts_not_evaluated_separately_from_results():
    sign_ins = [
        _signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}]),
        _signin(policies=[{"id": "other-policy", "result": "success"}]),  # no p1 entry
        _signin(policies=[]),  # CA evaluated nothing for this event
    ]
    cell = aggregate_cell(sign_ins, "p1")
    assert cell["counts"] == {"reportOnlySuccess": 1}
    assert cell["not_evaluated_count"] == 2
    assert cell["total_signins"] == 3


def test_aggregate_cell_unknown_result_gets_its_own_bucket():
    sign_ins = [_signin(policies=[{"id": "p1", "result": "somethingNew"}])]
    cell = aggregate_cell(sign_ins, "p1")
    assert cell["counts"] == {"unknownFutureValue": 1}


def test_aggregate_cell_handles_empty_signin_list():
    cell = aggregate_cell([], "p1")
    assert cell == {
        "not_collected": False,
        "counts": {},
        "not_evaluated_count": 0,
        "total_signins": 0,
        "sample_events": [],
    }


def test_aggregate_cell_caps_sample_events_at_max_samples():
    sign_ins = [_signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}])
                for _ in range(10)]
    cell = aggregate_cell(sign_ins, "p1", max_samples=3)
    assert len(cell["sample_events"]) == 3
    assert cell["total_signins"] == 10
    assert cell["counts"] == {"reportOnlySuccess": 10}  # counts unaffected by cap


def test_aggregate_cell_sample_event_shape():
    sign_ins = [_signin(policies=[{"id": "p1", "result": "reportOnlyFailure"}],
                         app="Exchange", city="Giza", country="EG", compliant=False)]
    cell = aggregate_cell(sign_ins, "p1")
    sample = cell["sample_events"][0]
    assert sample == {
        "timestamp": "2026-08-01T10:00:00Z",
        "app": "Exchange",
        "location": "Giza, EG",
        "device_compliant": False,
        "result_bucket": "reportOnlyFailure",
    }


def test_aggregate_cell_sample_event_result_bucket_is_not_evaluated_when_absent():
    sign_ins = [_signin(policies=[])]
    cell = aggregate_cell(sign_ins, "p1")
    assert cell["sample_events"][0]["result_bucket"] == "not_evaluated"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_aggregate.py -v`
Expected: FAIL — `extract_applied_policy_entry`/`aggregate_cell` not defined.

- [ ] **Step 3: Write minimal implementation**

```python
# aggregate.py (append)

def extract_applied_policy_entry(signin: dict, policy_id: str) -> dict | None:
    """Find the appliedConditionalAccessPolicies[] entry matching policy_id,
    or None if the policy has no entry at all on this sign-in — meaning CA
    did not evaluate this policy for this specific request.
    """
    for entry in signin.get("appliedConditionalAccessPolicies", []):
        if entry.get("id") == policy_id:
            return entry
    return None


def _format_location(signin: dict) -> str:
    location = signin.get("location") or {}
    city = location.get("city") or "Unknown"
    country = location.get("countryOrRegion") or "Unknown"
    return f"{city}, {country}"


def aggregate_cell(sign_ins: list[dict], policy_id: str, max_samples: int = 50) -> dict:
    """Aggregate one user's sign-ins against one policy id.

    Returns counts per known/unknown result bucket, a separate
    not_evaluated_count for sign-ins that never got a Graph evaluation entry
    for this policy at all, and up to max_samples raw sample events tagged
    with their result_bucket ("not_evaluated" is a valid bucket value here,
    distinct from every real Graph result string).
    """
    counts: dict[str, int] = {}
    not_evaluated_count = 0
    sample_events: list[dict] = []

    for signin in sign_ins:
        entry = extract_applied_policy_entry(signin, policy_id)
        if entry is None:
            not_evaluated_count += 1
            bucket = "not_evaluated"
        else:
            bucket = classify_result(entry.get("result", ""))
            counts[bucket] = counts.get(bucket, 0) + 1

        if len(sample_events) < max_samples:
            sample_events.append({
                "timestamp": signin.get("createdDateTime"),
                "app": signin.get("appDisplayName"),
                "location": _format_location(signin),
                "device_compliant": (signin.get("deviceDetail") or {}).get("isCompliant"),
                "result_bucket": bucket,
            })

    return {
        "not_collected": False,
        "counts": counts,
        "not_evaluated_count": not_evaluated_count,
        "total_signins": len(sign_ins),
        "sample_events": sample_events,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_aggregate.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add aggregate.py tests/test_aggregate.py
git commit -m "Add per-cell aggregation with evaluated/not-evaluated split"
```

---

### Task 3: Matrix assembly + per-policy totals (not-collected propagation)

**Files:**
- Modify: `aggregate.py`
- Test: `tests/test_aggregate.py`

**Interfaces:**
- Consumes: `aggregate_cell` (Task 2)
- Produces:
  `aggregate.aggregate_user_policy_matrix(users: list[dict], policies: list[dict], signins_by_user: dict[str, list[dict]], collection_errors: dict[str, str], max_samples: int = 50) -> dict`
  returning `{"matrix": {user_id: {policy_id: cell}}}`.
  `aggregate.aggregate_policy_totals(matrix: dict, policy_id: str) -> dict`
  returning `{"counts": dict[str, int], "not_evaluated_count": int, "not_collected_users": int, "total_signins": int}`.

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_aggregate.py (append)
from aggregate import aggregate_user_policy_matrix, aggregate_policy_totals

USERS = [
    {"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com"},
    {"id": "u2", "displayName": "Bob", "userPrincipalName": "bob@contoso.com"},
]
POLICIES = [
    {"id": "p1", "displayName": "Require MFA (report-only)", "state": "enabledForReportingButNotEnforced"},
]


def test_matrix_has_one_cell_per_user_per_policy():
    signins_by_user = {
        "u1": [_signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}])],
        "u2": [_signin(policies=[{"id": "p1", "result": "reportOnlyNotApplied"}])],
    }
    result = aggregate_user_policy_matrix(USERS, POLICIES, signins_by_user, {})
    matrix = result["matrix"]
    assert set(matrix.keys()) == {"u1", "u2"}
    assert matrix["u1"]["p1"]["counts"] == {"reportOnlySuccess": 1}
    assert matrix["u2"]["p1"]["counts"] == {"reportOnlyNotApplied": 1}


def test_matrix_marks_not_collected_users_without_calling_aggregate_cell():
    signins_by_user = {"u1": [_signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}])]}
    collection_errors = {"u2": "403 insufficient privileges reading AuditLog for bob@contoso.com"}
    result = aggregate_user_policy_matrix(USERS, POLICIES, signins_by_user, collection_errors)
    assert result["matrix"]["u2"]["p1"] == {
        "not_collected": True,
        "reason": "403 insufficient privileges reading AuditLog for bob@contoso.com",
    }
    assert result["matrix"]["u1"]["p1"]["not_collected"] is False


def test_policy_totals_sum_across_users_and_track_not_collected_separately():
    signins_by_user = {
        "u1": [_signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}]),
               _signin(policies=[{"id": "p1", "result": "reportOnlySuccess"}])],
        "u2": [_signin(policies=[])],  # not evaluated
    }
    collection_errors = {}
    result = aggregate_user_policy_matrix(
        USERS + [{"id": "u3", "displayName": "Carol", "userPrincipalName": "carol@contoso.com"}],
        POLICIES,
        signins_by_user,
        {"u3": "token expired mid-pull"},
    )
    totals = aggregate_policy_totals(result["matrix"], "p1")
    assert totals["counts"] == {"reportOnlySuccess": 2}
    assert totals["not_evaluated_count"] == 1
    assert totals["not_collected_users"] == 1
    assert totals["total_signins"] == 3
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_aggregate.py -v`
Expected: FAIL — `aggregate_user_policy_matrix`/`aggregate_policy_totals` not defined.

- [ ] **Step 3: Write minimal implementation**

```python
# aggregate.py (append)

def aggregate_user_policy_matrix(
    users: list[dict],
    policies: list[dict],
    signins_by_user: dict[str, list[dict]],
    collection_errors: dict[str, str],
    max_samples: int = 50,
) -> dict:
    """Build the full user x policy matrix.

    A user present in collection_errors gets a {"not_collected": True,
    "reason": ...} marker for every policy cell instead of a computed
    aggregate — collection failure is a per-user fact, not a per-policy one,
    so it applies uniformly across that user's row.
    """
    matrix: dict[str, dict[str, dict]] = {}
    for user in users:
        user_id = user["id"]
        matrix[user_id] = {}
        if user_id in collection_errors:
            marker = {"not_collected": True, "reason": collection_errors[user_id]}
            for policy in policies:
                matrix[user_id][policy["id"]] = marker
            continue

        sign_ins = signins_by_user.get(user_id, [])
        for policy in policies:
            matrix[user_id][policy["id"]] = aggregate_cell(
                sign_ins, policy["id"], max_samples=max_samples
            )

    return {"matrix": matrix}


def aggregate_policy_totals(matrix: dict, policy_id: str) -> dict:
    """Sum one policy's column across every user in the matrix."""
    counts: dict[str, int] = {}
    not_evaluated_count = 0
    not_collected_users = 0
    total_signins = 0

    for user_id, policy_cells in matrix.items():
        cell = policy_cells[policy_id]
        if cell["not_collected"]:
            not_collected_users += 1
            continue
        for bucket, count in cell["counts"].items():
            counts[bucket] = counts.get(bucket, 0) + count
        not_evaluated_count += cell["not_evaluated_count"]
        total_signins += cell["total_signins"]

    return {
        "counts": counts,
        "not_evaluated_count": not_evaluated_count,
        "not_collected_users": not_collected_users,
        "total_signins": total_signins,
    }
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_aggregate.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add aggregate.py tests/test_aggregate.py
git commit -m "Add matrix assembly and per-policy totals with not-collected propagation"
```

---

### Task 4: MSAL device-code authenticator

**Files:**
- Create: `graph_client.py`
- Test: `tests/test_graph_client.py`

**Interfaces:**
- Consumes: nothing new
- Produces: `graph_client.GRAPH_CLI_CLIENT_ID: str`, `graph_client.DEFAULT_SCOPES: list[str]`,
  `graph_client.DeviceCodeAuthenticator` class with `.acquire_token() -> str`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_graph_client.py
from unittest.mock import MagicMock, patch

from graph_client import DeviceCodeAuthenticator, GRAPH_CLI_CLIENT_ID, DEFAULT_SCOPES


def test_default_scopes_match_spec():
    assert DEFAULT_SCOPES == [
        "AuditLog.Read.All", "Policy.Read.All", "User.Read.All", "Group.Read.All",
    ]


def test_client_id_is_first_party_graph_cli_app():
    assert GRAPH_CLI_CLIENT_ID == "14d82eec-204b-4c2f-b7e8-296a70dab67e"


@patch("graph_client.msal.PublicClientApplication")
def test_acquire_token_runs_device_flow_and_returns_access_token(mock_app_class):
    mock_app = MagicMock()
    mock_app_class.return_value = mock_app
    mock_app.initiate_device_flow.return_value = {
        "user_code": "ABC123",
        "verification_uri": "https://microsoft.com/devicelogin",
        "message": "To sign in, use a web browser...",
    }
    mock_app.acquire_token_by_device_flow.return_value = {
        "access_token": "fake-token-value",
    }

    authenticator = DeviceCodeAuthenticator()
    token = authenticator.acquire_token()

    assert token == "fake-token-value"
    mock_app_class.assert_called_once_with(
        GRAPH_CLI_CLIENT_ID,
        authority="https://login.microsoftonline.com/organizations",
    )
    mock_app.initiate_device_flow.assert_called_once_with(scopes=DEFAULT_SCOPES)
    mock_app.acquire_token_by_device_flow.assert_called_once_with(
        mock_app.initiate_device_flow.return_value
    )


@patch("graph_client.msal.PublicClientApplication")
def test_acquire_token_raises_on_missing_access_token(mock_app_class):
    mock_app = MagicMock()
    mock_app_class.return_value = mock_app
    mock_app.initiate_device_flow.return_value = {"user_code": "ABC123", "message": "..."}
    mock_app.acquire_token_by_device_flow.return_value = {
        "error": "authorization_pending",
        "error_description": "The user has not yet completed sign-in.",
    }

    authenticator = DeviceCodeAuthenticator()
    try:
        authenticator.acquire_token()
        assert False, "expected RuntimeError"
    except RuntimeError as exc:
        assert "authorization_pending" in str(exc)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_graph_client.py -v`
Expected: FAIL — `graph_client` module does not exist yet.

- [ ] **Step 3: Write minimal implementation**

```python
# graph_client.py
"""Microsoft Graph auth and HTTP access for the CA Report-Only Analyzer.

All network I/O lives in this module, kept separate from aggregate.py's
pure logic so the aggregation rules can be unit-tested without a live
tenant.
"""
import time

import msal
import requests

# Microsoft's own first-party "Microsoft Graph Command Line Tools" public
# client. Using it means no app registration is ever required in the
# target tenant — same mechanism the GBG Assessment Tool uses.
GRAPH_CLI_CLIENT_ID = "14d82eec-204b-4c2f-b7e8-296a70dab67e"
AUTHORITY = "https://login.microsoftonline.com/organizations"
DEFAULT_SCOPES = ["AuditLog.Read.All", "Policy.Read.All", "User.Read.All", "Group.Read.All"]
GRAPH_BASE = "https://graph.microsoft.com/v1.0"


class GraphPermissionError(Exception):
    """Raised when Graph returns 403 for a specific call — the caller
    should record this as 'not collected', never as an empty/zero result.
    """


class GraphThrottledError(Exception):
    """Raised when Graph keeps returning 429 past the retry budget."""


class DeviceCodeAuthenticator:
    """Wraps MSAL's device-code flow against the first-party Graph CLI client.

    offline_access is intentionally not in DEFAULT_SCOPES: MSAL public
    clients get a refresh token automatically, and passing offline_access
    explicitly triggers an MSAL warning.
    """

    def __init__(self, client_id: str = GRAPH_CLI_CLIENT_ID,
                 authority: str = AUTHORITY, scopes: list[str] | None = None):
        self.client_id = client_id
        self.authority = authority
        self.scopes = scopes or DEFAULT_SCOPES
        self._app = msal.PublicClientApplication(self.client_id, authority=self.authority)

    def acquire_token(self) -> str:
        flow = self._app.initiate_device_flow(scopes=self.scopes)
        if "user_code" not in flow:
            raise RuntimeError(f"Failed to start device flow: {flow}")
        print(flow.get("message", f"Go to {flow.get('verification_uri')} and enter code {flow.get('user_code')}"))

        result = self._app.acquire_token_by_device_flow(flow)
        if "access_token" not in result:
            raise RuntimeError(
                f"Device code sign-in failed: {result.get('error')} - "
                f"{result.get('error_description')}"
            )
        return result["access_token"]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_graph_client.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add graph_client.py tests/test_graph_client.py
git commit -m "Add MSAL device-code authenticator against first-party Graph CLI client"
```

---

### Task 5: Paginated GET with 429 backoff and 403 handling

**Files:**
- Modify: `graph_client.py`
- Test: `tests/test_graph_client.py`

**Interfaces:**
- Consumes: `GraphPermissionError`, `GraphThrottledError` (Task 4)
- Produces: `graph_client.request_with_backoff(session, method, url, max_retries=5, **kwargs) -> requests.Response`,
  `graph_client.graph_get_all_pages(session, url, headers, params=None) -> list[dict]`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_graph_client.py (append)
from unittest.mock import MagicMock, call
import pytest

from graph_client import request_with_backoff, graph_get_all_pages, GraphPermissionError, GraphThrottledError


class FakeResponse:
    def __init__(self, status_code, json_data=None, headers=None):
        self.status_code = status_code
        self._json_data = json_data or {}
        self.headers = headers or {}
        self.text = str(json_data)

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"{self.status_code} error")


import requests  # noqa: E402  (import after FakeResponse uses requests.HTTPError above)


def test_request_with_backoff_returns_response_on_success():
    session = MagicMock()
    session.request.return_value = FakeResponse(200, {"value": []})
    response = request_with_backoff(session, "GET", "https://graph.microsoft.com/v1.0/users")
    assert response.status_code == 200


def test_request_with_backoff_raises_permission_error_on_403():
    session = MagicMock()
    session.request.return_value = FakeResponse(403, {"error": {"message": "Forbidden"}})
    with pytest.raises(GraphPermissionError):
        request_with_backoff(session, "GET", "https://graph.microsoft.com/v1.0/auditLogs/signIns")


def test_request_with_backoff_respects_retry_after_then_succeeds(monkeypatch):
    sleeps = []
    monkeypatch.setattr("graph_client.time.sleep", lambda s: sleeps.append(s))

    session = MagicMock()
    session.request.side_effect = [
        FakeResponse(429, headers={"Retry-After": "2"}),
        FakeResponse(200, {"value": []}),
    ]
    response = request_with_backoff(session, "GET", "https://graph.microsoft.com/v1.0/users")
    assert response.status_code == 200
    assert sleeps == [2.0]


def test_request_with_backoff_gives_up_after_max_retries(monkeypatch):
    monkeypatch.setattr("graph_client.time.sleep", lambda s: None)
    session = MagicMock()
    session.request.return_value = FakeResponse(429, headers={"Retry-After": "1"})
    with pytest.raises(GraphThrottledError):
        request_with_backoff(session, "GET", "https://graph.microsoft.com/v1.0/users", max_retries=3)
    assert session.request.call_count == 3


def test_graph_get_all_pages_follows_next_link():
    session = MagicMock()
    session.request.side_effect = [
        FakeResponse(200, {
            "value": [{"id": "1"}, {"id": "2"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=abc",
        }),
        FakeResponse(200, {"value": [{"id": "3"}]}),
    ]
    results = graph_get_all_pages(session, "https://graph.microsoft.com/v1.0/users", headers={})
    assert results == [{"id": "1"}, {"id": "2"}, {"id": "3"}]
    assert session.request.call_count == 2
    assert session.request.call_args_list[1] == call(
        "GET", "https://graph.microsoft.com/v1.0/users?$skiptoken=abc", headers={}, params=None
    )
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_graph_client.py -v`
Expected: FAIL — `request_with_backoff`/`graph_get_all_pages` not defined.

- [ ] **Step 3: Write minimal implementation**

```python
# graph_client.py (append)

def request_with_backoff(session, method: str, url: str, max_retries: int = 5, **kwargs) -> "requests.Response":
    """Issue one HTTP request, retrying on 429 with Retry-After (or a
    1-second default), raising GraphPermissionError immediately on 403
    (a caller should record this as "not collected", never retry it away),
    and GraphThrottledError if 429s exhaust the retry budget.
    """
    for attempt in range(max_retries):
        response = session.request(method, url, **kwargs)
        if response.status_code == 403:
            raise GraphPermissionError(f"{method} {url} -> 403: {response.text}")
        if response.status_code == 429:
            if attempt == max_retries - 1:
                break
            retry_after = float(response.headers.get("Retry-After", 1))
            time.sleep(retry_after)
            continue
        response.raise_for_status()
        return response
    raise GraphThrottledError(f"{method} {url} exhausted {max_retries} retries on 429")


def graph_get_all_pages(session, url: str, headers: dict, params: dict | None = None) -> list[dict]:
    """Follow @odata.nextLink until Graph stops returning one, collecting
    every page's 'value' array into one flat list of plain dicts.
    """
    results: list[dict] = []
    next_url = url
    next_params = params
    while next_url:
        response = request_with_backoff(session, "GET", next_url, headers=headers, params=next_params)
        body = response.json()
        results.extend(body.get("value", []))
        next_url = body.get("@odata.nextLink")
        next_params = None  # nextLink already carries all needed query params
    return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_graph_client.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add graph_client.py tests/test_graph_client.py
git commit -m "Add paginated Graph GET with 429 backoff and 403 handling"
```

---

### Task 6: Discovery + sign-in-log fetch functions

**Files:**
- Modify: `graph_client.py`
- Test: `tests/test_graph_client.py`

**Interfaces:**
- Consumes: `graph_get_all_pages` (Task 5)
- Produces:
  `graph_client.fetch_ca_policies(session, headers) -> list[dict]`,
  `graph_client.fetch_users(session, headers) -> list[dict]`,
  `graph_client.fetch_groups(session, headers) -> list[dict]`,
  `graph_client.fetch_group_members(session, headers, group_id: str) -> list[dict]`,
  `graph_client.fetch_signins_for_user(session, headers, user_principal_name: str, since_iso: str) -> list[dict]`,
  `graph_client.fetch_signins_all(session, headers, since_iso: str) -> list[dict]`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_graph_client.py (append)
from graph_client import (
    fetch_ca_policies, fetch_users, fetch_groups, fetch_group_members,
    fetch_signins_for_user, fetch_signins_all, GRAPH_BASE,
)


def test_fetch_ca_policies_calls_expected_url_and_returns_list(monkeypatch):
    captured = {}

    def fake_graph_get_all_pages(session, url, headers, params=None):
        captured["url"] = url
        captured["params"] = params
        return [{"id": "p1", "displayName": "Require MFA", "state": "enabled"}]

    monkeypatch.setattr("graph_client.graph_get_all_pages", fake_graph_get_all_pages)
    result = fetch_ca_policies(session=MagicMock(), headers={"Authorization": "Bearer x"})
    assert captured["url"] == f"{GRAPH_BASE}/identity/conditionalAccess/policies"
    assert result == [{"id": "p1", "displayName": "Require MFA", "state": "enabled"}]


def test_fetch_users_selects_lightweight_fields(monkeypatch):
    captured = {}

    def fake_graph_get_all_pages(session, url, headers, params=None):
        captured["params"] = params
        return [{"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com"}]

    monkeypatch.setattr("graph_client.graph_get_all_pages", fake_graph_get_all_pages)
    result = fetch_users(session=MagicMock(), headers={})
    assert captured["params"] == {"$select": "id,displayName,userPrincipalName"}
    assert result[0]["userPrincipalName"] == "alice@contoso.com"


def test_fetch_groups_selects_lightweight_fields(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "graph_client.graph_get_all_pages",
        lambda session, url, headers, params=None: captured.setdefault("params", params) or [],
    )
    fetch_groups(session=MagicMock(), headers={})
    assert captured["params"] == {"$select": "id,displayName"}


def test_fetch_group_members_uses_group_id_in_url(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "graph_client.graph_get_all_pages",
        lambda session, url, headers, params=None: captured.setdefault("url", url) or [],
    )
    fetch_group_members(session=MagicMock(), headers={}, group_id="g1")
    assert captured["url"] == f"{GRAPH_BASE}/groups/g1/members"


def test_fetch_signins_for_user_filters_by_upn_and_date(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "graph_client.graph_get_all_pages",
        lambda session, url, headers, params=None: captured.setdefault("params", params) or [],
    )
    fetch_signins_for_user(session=MagicMock(), headers={},
                            user_principal_name="alice@contoso.com", since_iso="2026-08-01T00:00:00Z")
    assert captured["params"] == {
        "$filter": "userPrincipalName eq 'alice@contoso.com' and createdDateTime ge 2026-08-01T00:00:00Z"
    }


def test_fetch_signins_all_filters_by_date_only(monkeypatch):
    captured = {}
    monkeypatch.setattr(
        "graph_client.graph_get_all_pages",
        lambda session, url, headers, params=None: captured.setdefault("params", params) or [],
    )
    fetch_signins_all(session=MagicMock(), headers={}, since_iso="2026-08-01T00:00:00Z")
    assert captured["params"] == {"$filter": "createdDateTime ge 2026-08-01T00:00:00Z"}


def test_fetch_signins_for_user_propagates_permission_error(monkeypatch):
    def raise_permission_error(*args, **kwargs):
        raise GraphPermissionError("403 on this user")

    monkeypatch.setattr("graph_client.graph_get_all_pages", raise_permission_error)
    with pytest.raises(GraphPermissionError):
        fetch_signins_for_user(session=MagicMock(), headers={},
                                user_principal_name="bob@contoso.com", since_iso="2026-08-01T00:00:00Z")
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_graph_client.py -v`
Expected: FAIL — the six `fetch_*` functions are not defined.

- [ ] **Step 3: Write minimal implementation**

```python
# graph_client.py (append)

def fetch_ca_policies(session, headers: dict) -> list[dict]:
    return graph_get_all_pages(session, f"{GRAPH_BASE}/identity/conditionalAccess/policies", headers)


def fetch_users(session, headers: dict) -> list[dict]:
    return graph_get_all_pages(
        session, f"{GRAPH_BASE}/users", headers,
        params={"$select": "id,displayName,userPrincipalName"},
    )


def fetch_groups(session, headers: dict) -> list[dict]:
    return graph_get_all_pages(
        session, f"{GRAPH_BASE}/groups", headers,
        params={"$select": "id,displayName"},
    )


def fetch_group_members(session, headers: dict, group_id: str) -> list[dict]:
    return graph_get_all_pages(session, f"{GRAPH_BASE}/groups/{group_id}/members", headers)


def fetch_signins_for_user(session, headers: dict, user_principal_name: str, since_iso: str) -> list[dict]:
    filter_expr = f"userPrincipalName eq '{user_principal_name}' and createdDateTime ge {since_iso}"
    return graph_get_all_pages(
        session, f"{GRAPH_BASE}/auditLogs/signIns", headers,
        params={"$filter": filter_expr},
    )


def fetch_signins_all(session, headers: dict, since_iso: str) -> list[dict]:
    return graph_get_all_pages(
        session, f"{GRAPH_BASE}/auditLogs/signIns", headers,
        params={"$filter": f"createdDateTime ge {since_iso}"},
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_graph_client.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add graph_client.py tests/test_graph_client.py
git commit -m "Add Graph discovery and sign-in-log fetch functions"
```

---

### Task 7: User-scope resolution (all / specific users / groups, deduped)

**Files:**
- Create: `pipeline.py`
- Test: `tests/test_pipeline.py`

**Interfaces:**
- Consumes: nothing new (takes a `fetch_group_members`-shaped callable as a parameter,
  doesn't import graph_client directly — keeps this module pure/testable)
- Produces: `pipeline.resolve_user_scope(selection: dict, discovered_users: list[dict], fetch_group_members) -> list[dict]`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_pipeline.py
from pipeline import resolve_user_scope

DISCOVERED_USERS = [
    {"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com"},
    {"id": "u2", "displayName": "Bob", "userPrincipalName": "bob@contoso.com"},
    {"id": "u3", "displayName": "Carol", "userPrincipalName": "carol@contoso.com"},
]


def test_all_users_scope_returns_full_discovered_list():
    selection = {"all_users": True, "user_ids": [], "group_ids": []}
    result = resolve_user_scope(selection, DISCOVERED_USERS, fetch_group_members=lambda gid: [])
    assert result == DISCOVERED_USERS


def test_specific_users_scope_returns_only_selected():
    selection = {"all_users": False, "user_ids": ["u2"], "group_ids": []}
    result = resolve_user_scope(selection, DISCOVERED_USERS, fetch_group_members=lambda gid: [])
    assert result == [DISCOVERED_USERS[1]]


def test_groups_scope_expands_via_fetch_group_members():
    def fake_fetch_group_members(group_id):
        assert group_id == "g1"
        return [{"id": "u1"}, {"id": "u3"}]

    selection = {"all_users": False, "user_ids": [], "group_ids": ["g1"]}
    result = resolve_user_scope(selection, DISCOVERED_USERS, fake_fetch_group_members)
    assert {u["id"] for u in result} == {"u1", "u3"}


def test_mixed_users_and_groups_are_unioned_and_deduped():
    def fake_fetch_group_members(group_id):
        return [{"id": "u2"}]  # overlaps with the individually selected user below

    selection = {"all_users": False, "user_ids": ["u2"], "group_ids": ["g1"]}
    result = resolve_user_scope(selection, DISCOVERED_USERS, fake_fetch_group_members)
    assert [u["id"] for u in result] == ["u2"]  # deduped, not doubled


def test_group_member_not_in_discovered_users_is_skipped():
    def fake_fetch_group_members(group_id):
        return [{"id": "u-not-discovered"}]

    selection = {"all_users": False, "user_ids": [], "group_ids": ["g1"]}
    result = resolve_user_scope(selection, DISCOVERED_USERS, fake_fetch_group_members)
    assert result == []
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_pipeline.py -v`
Expected: FAIL — `pipeline` module does not exist yet.

- [ ] **Step 3: Write minimal implementation**

```python
# pipeline.py
"""Pure scope-resolution logic — no network I/O. fetch_group_members is
injected as a callable so this module stays testable without graph_client.
"""


def resolve_user_scope(selection: dict, discovered_users: list[dict], fetch_group_members) -> list[dict]:
    """Turn a picker-page selection into a concrete, deduped list of full
    user records (each pulled from discovered_users, never invented).

    selection shape: {"all_users": bool, "user_ids": [str], "group_ids": [str]}
    fetch_group_members: callable(group_id: str) -> list[{"id": str, ...}]
    """
    if selection.get("all_users"):
        return list(discovered_users)

    users_by_id = {user["id"]: user for user in discovered_users}
    selected_ids: dict[str, None] = {}  # ordered set

    for user_id in selection.get("user_ids", []):
        if user_id in users_by_id:
            selected_ids[user_id] = None

    for group_id in selection.get("group_ids", []):
        for member in fetch_group_members(group_id):
            member_id = member["id"]
            if member_id in users_by_id:
                selected_ids[member_id] = None

    return [users_by_id[user_id] for user_id in selected_ids]
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_pipeline.py -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add pipeline.py tests/test_pipeline.py
git commit -m "Add user-scope resolution for all/specific-users/groups selection"
```

---

### Task 8: Picker page + transient selection server

**Files:**
- Create: `templates/picker.html`
- Create: `selection_server.py`
- Test: `tests/test_selection_server.py`

**Interfaces:**
- Consumes: nothing new
- Produces: `selection_server.run_selection_server(users: list[dict], groups: list[dict], policies: list[dict], template_path: str, open_browser: bool = True) -> dict`
  returning the selection dict `{"all_users": bool, "user_ids": list[str], "group_ids": list[str], "policy_ids": list[str], "days": int}`.

- [ ] **Step 1: Write the picker HTML template**

```html
<!-- templates/picker.html -->
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CA Report-Only Policy Analyzer — Select Scope</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 720px; margin: 2rem auto; padding: 0 1rem; }
  fieldset { margin-bottom: 1.5rem; padding: 1rem; }
  input[type="search"] { width: 100%; padding: 0.5rem; margin-bottom: 0.5rem; box-sizing: border-box; }
  .list-box { max-height: 220px; overflow-y: auto; border: 1px solid #ccc; padding: 0.5rem; }
  label { display: block; padding: 0.15rem 0; }
  button { padding: 0.6rem 1.2rem; font-size: 1rem; }
  #status { margin-top: 1rem; color: #555; }
</style>
</head>
<body>
<h1>CA Report-Only Policy Analyzer</h1>

<fieldset>
  <legend>Users</legend>
  <label><input type="checkbox" id="all-users-checkbox"> All users</label>
  <input type="search" id="user-search" placeholder="Search users...">
  <div class="list-box" id="user-list"></div>
</fieldset>

<fieldset>
  <legend>Groups</legend>
  <input type="search" id="group-search" placeholder="Search groups...">
  <div class="list-box" id="group-list"></div>
</fieldset>

<fieldset>
  <legend>Policies</legend>
  <div class="list-box" id="policy-list"></div>
</fieldset>

<fieldset>
  <legend>Day range</legend>
  <label>Days back: <input type="number" id="days-input" value="30" min="1"></label>
  <div id="retention-warning" style="display:none;color:#a33;">
    Entra ID sign-in log retention is typically 30 days — results beyond that will likely be empty.
  </div>
</fieldset>

<button id="generate-btn">Generate</button>
<div id="status"></div>

<script>
  const USERS = __USERS_JSON__;
  const GROUPS = __GROUPS_JSON__;
  const POLICIES = __POLICIES_JSON__;

  function renderCheckboxList(container, items, labelKey) {
    container.innerHTML = "";
    for (const item of items) {
      const label = document.createElement("label");
      const checkbox = document.createElement("input");
      checkbox.type = "checkbox";
      checkbox.value = item.id;
      checkbox.dataset.role = container.dataset.role;
      label.appendChild(checkbox);
      label.appendChild(document.createTextNode(" " + item[labelKey]));
      container.appendChild(label);
    }
  }

  const userList = document.getElementById("user-list");
  userList.dataset.role = "user";
  const groupList = document.getElementById("group-list");
  groupList.dataset.role = "group";
  const policyList = document.getElementById("policy-list");
  policyList.dataset.role = "policy";

  renderCheckboxList(userList, USERS, "displayName");
  renderCheckboxList(groupList, GROUPS, "displayName");
  renderCheckboxList(policyList, POLICIES, "displayName");

  document.getElementById("user-search").addEventListener("input", (e) => {
    const term = e.target.value.toLowerCase();
    renderCheckboxList(userList, USERS.filter(u => u.displayName.toLowerCase().includes(term)), "displayName");
  });
  document.getElementById("group-search").addEventListener("input", (e) => {
    const term = e.target.value.toLowerCase();
    renderCheckboxList(groupList, GROUPS.filter(g => g.displayName.toLowerCase().includes(term)), "displayName");
  });

  const daysInput = document.getElementById("days-input");
  const retentionWarning = document.getElementById("retention-warning");
  daysInput.addEventListener("input", () => {
    retentionWarning.style.display = Number(daysInput.value) > 30 ? "block" : "none";
  });

  document.getElementById("generate-btn").addEventListener("click", () => {
    const allUsers = document.getElementById("all-users-checkbox").checked;
    const selectedUserIds = Array.from(userList.querySelectorAll("input:checked")).map(cb => cb.value);
    const selectedGroupIds = Array.from(groupList.querySelectorAll("input:checked")).map(cb => cb.value);
    const selectedPolicyIds = Array.from(policyList.querySelectorAll("input:checked")).map(cb => cb.value);

    const payload = {
      all_users: allUsers,
      user_ids: selectedUserIds,
      group_ids: selectedGroupIds,
      policy_ids: selectedPolicyIds,
      days: Number(daysInput.value),
    };

    document.getElementById("status").textContent = "Submitting selection...";
    fetch("/submit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    }).then(() => {
      document.getElementById("status").textContent = "Selection received — you can close this tab.";
    }).catch(() => {
      document.getElementById("status").textContent = "Submit failed — check the terminal.";
    });
  });
</script>
</body>
</html>
```

- [ ] **Step 2: Write the failing tests for the server**

```python
# tests/test_selection_server.py
import json
import threading
from unittest.mock import patch

import requests

from selection_server import run_selection_server

USERS = [{"id": "u1", "displayName": "Alice"}]
GROUPS = [{"id": "g1", "displayName": "Engineering"}]
POLICIES = [{"id": "p1", "displayName": "Require MFA (report-only)"}]
TEMPLATE_PATH = "templates/picker.html"


def _submit_after_delay(port, payload, delay=0.2):
    def _worker():
        import time
        time.sleep(delay)
        requests.post(f"http://127.0.0.1:{port}/submit", json=payload, timeout=5)
    threading.Thread(target=_worker, daemon=True).start()


@patch("selection_server.webbrowser.open")
def test_get_root_embeds_users_groups_and_policies(mock_open):
    result_holder = {}

    def run_and_capture():
        result_holder["selection"] = run_selection_server(
            USERS, GROUPS, POLICIES, TEMPLATE_PATH, open_browser=True
        )

    # We need the port before we can GET, so start the server in a thread
    # via a small wrapper that exposes the bound port through the mocked
    # webbrowser.open call argument (the URL it was told to open).
    thread = threading.Thread(target=run_and_capture, daemon=True)
    thread.start()

    # Wait for webbrowser.open to have been called with the server URL.
    import time
    for _ in range(50):
        if mock_open.called:
            break
        time.sleep(0.05)
    assert mock_open.called
    url = mock_open.call_args[0][0]

    page = requests.get(url, timeout=5)
    assert page.status_code == 200
    assert "Alice" in page.text
    assert "Engineering" in page.text
    assert "Require MFA (report-only)" in page.text

    _submit_after_delay(url.split(":")[-1].rstrip("/"), {
        "all_users": False, "user_ids": ["u1"], "group_ids": [], "policy_ids": ["p1"], "days": 30,
    }, delay=0.05)
    thread.join(timeout=5)
    assert result_holder["selection"] == {
        "all_users": False, "user_ids": ["u1"], "group_ids": [], "policy_ids": ["p1"], "days": 30,
    }


@patch("selection_server.webbrowser.open")
def test_submit_returns_exact_payload_and_server_shuts_down(mock_open):
    result_holder = {}
    thread = threading.Thread(
        target=lambda: result_holder.update(
            selection=run_selection_server(USERS, GROUPS, POLICIES, TEMPLATE_PATH, open_browser=True)
        ),
        daemon=True,
    )
    thread.start()

    import time
    for _ in range(50):
        if mock_open.called:
            break
        time.sleep(0.05)
    url = mock_open.call_args[0][0]
    port = url.rsplit(":", 1)[1].rstrip("/")

    payload = {"all_users": True, "user_ids": [], "group_ids": [], "policy_ids": ["p1"], "days": 7}
    response = requests.post(f"http://127.0.0.1:{port}/submit", json=payload, timeout=5)
    assert response.status_code == 200

    thread.join(timeout=5)
    assert not thread.is_alive()
    assert result_holder["selection"] == payload
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_selection_server.py -v`
Expected: FAIL — `selection_server` module does not exist yet.

- [ ] **Step 4: Write minimal implementation**

```python
# selection_server.py
"""Transient loopback-only HTTP server for the scope-selection picker page.

Exists only for the duration of one selection round-trip: serve the
picker page with data embedded, receive one POST /submit, then shut
itself down and hand the parsed selection back to the caller.
"""
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _render_picker_html(template_path: str, users: list[dict], groups: list[dict], policies: list[dict]) -> str:
    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()
    return (
        template
        .replace("__USERS_JSON__", json.dumps(users))
        .replace("__GROUPS_JSON__", json.dumps(groups))
        .replace("__POLICIES_JSON__", json.dumps(policies))
    )


def run_selection_server(
    users: list[dict], groups: list[dict], policies: list[dict],
    template_path: str, open_browser: bool = True,
) -> dict:
    page_html = _render_picker_html(template_path, users, groups, policies)
    result: dict = {}
    submitted = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # keep test/CLI output quiet

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                body = page_html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path != "/submit":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                return
            result["selection"] = payload
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            submitted.set()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    url = f"http://127.0.0.1:{port}/"
    if open_browser:
        webbrowser.open(url)

    submitted.wait()
    server.shutdown()
    server_thread.join(timeout=5)

    return result["selection"]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_selection_server.py -v`
Expected: PASS (both tests)

- [ ] **Step 6: Commit**

```bash
git add templates/picker.html selection_server.py tests/test_selection_server.py
git commit -m "Add picker page and transient loopback selection server"
```

---

### Task 9: Static HTML report renderer

**Files:**
- Create: `templates/report.html`
- Create: `report_renderer.py`
- Test: `tests/test_report_renderer.py`

**Interfaces:**
- Consumes: matrix shape from `aggregate.aggregate_user_policy_matrix` (Task 3)
- Produces: `report_renderer.render_report(matrix_result: dict, users: list[dict], policies: list[dict], meta: dict, template_path: str) -> str`,
  `report_renderer.write_report(html: str, output_path: str) -> None`

- [ ] **Step 1: Write the report HTML template**

```html
<!-- templates/report.html -->
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>CA Report-Only Policy Analyzer — Report</title>
<style>
  body { font-family: system-ui, sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }
  .cards { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }
  .card { border: 1px solid #ccc; border-radius: 6px; padding: 1rem; min-width: 160px; }
  .card .value { font-size: 1.6rem; font-weight: bold; }
  table { border-collapse: collapse; width: 100%; margin-bottom: 2rem; }
  th, td { border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.85rem; }
  .cell-would-apply { background: #d7f0d7; }
  .cell-would-not-apply { background: #f5d7d7; }
  .cell-mixed { background: #f5eccb; }
  .cell-not-collected { background: #ddd; font-style: italic; }
  .caveats { background: #fff8e1; border: 1px solid #e0c76a; padding: 1rem; margin-top: 2rem; }
  .drill-down { display: none; border: 1px solid #ccc; padding: 0.5rem; margin-top: 0.5rem; font-size: 0.8rem; }
  .bar { height: 18px; background: #4a90c8; display: inline-block; }
</style>
</head>
<body>
<h1>CA Report-Only Policy Analyzer — Report</h1>
<div id="summary-cards" class="cards"></div>
<h2>User &times; Policy Matrix</h2>
<table id="matrix-table"></table>
<div id="drill-down" class="drill-down"></div>
<h2>Per-Policy Result Distribution</h2>
<div id="policy-charts"></div>
<div class="caveats">
  <strong>Caveats</strong>
  <ul>
    <li>Results assume each policy's report-only/enforced mode was constant across the analyzed window — Graph only exposes the current policy list, not its history.</li>
    <li>Interactive user sign-ins only; workload-identity/service-principal sign-ins are not included.</li>
    <li>Requested vs. actual covered date range is shown above; a requested range beyond sign-in log retention will show fewer days actually covered.</li>
  </ul>
</div>

<script>
  const REPORT_DATA = __REPORT_DATA__;

  function renderSummaryCards() {
    const container = document.getElementById("summary-cards");
    const cards = [
      ["Sign-ins pulled", REPORT_DATA.meta.total_signins],
      ["Users analyzed", REPORT_DATA.users.length],
      ["Policies analyzed", REPORT_DATA.policies.length],
      ["Requested days", REPORT_DATA.meta.requested_days],
    ];
    for (const [label, value] of cards) {
      const div = document.createElement("div");
      div.className = "card";
      div.innerHTML = `<div>${label}</div><div class="value">${value}</div>`;
      container.appendChild(div);
    }
  }

  function dominantClass(cell) {
    if (cell.not_collected) return "cell-not-collected";
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
    if (cell.not_collected) return "Not collected";
    const total = Object.values(cell.counts || {}).reduce((a, b) => a + b, 0);
    return `${total} evaluated / ${cell.not_evaluated_count} not evaluated`;
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
        td.className = dominantClass(cell);
        td.textContent = cellLabel(cell);
        td.style.cursor = "pointer";
        td.addEventListener("click", () => showDrillDown(user, policy, cell));
        row.appendChild(td);
      }
      table.appendChild(row);
    }
  }

  function showDrillDown(user, policy, cell) {
    const el = document.getElementById("drill-down");
    if (cell.not_collected) {
      el.innerHTML = `<strong>${user.displayName} / ${policy.displayName}</strong>: not collected — ${cell.reason}`;
    } else {
      const rows = (cell.sample_events || []).map(e =>
        `<tr><td>${e.timestamp}</td><td>${e.app}</td><td>${e.location}</td><td>${e.result_bucket}</td></tr>`
      ).join("");
      el.innerHTML = `<strong>${user.displayName} / ${policy.displayName}</strong> — sample events:
        <table><tr><th>Time</th><th>App</th><th>Location</th><th>Result</th></tr>${rows}</table>`;
    }
    el.style.display = "block";
  }

  function renderPolicyCharts() {
    const container = document.getElementById("policy-charts");
    for (const policy of REPORT_DATA.policies) {
      const totals = REPORT_DATA.policy_totals[policy.id];
      const total = Object.values(totals.counts).reduce((a, b) => a + b, 0) + totals.not_evaluated_count;
      const div = document.createElement("div");
      div.innerHTML = `<h3>${policy.displayName}</h3>`;
      for (const [bucket, count] of Object.entries(totals.counts)) {
        const width = total > 0 ? Math.round((count / total) * 300) : 0;
        div.innerHTML += `<div>${bucket}: <span class="bar" style="width:${width}px"></span> ${count}</div>`;
      }
      div.innerHTML += `<div>not_evaluated: <span class="bar" style="width:${total > 0 ? Math.round((totals.not_evaluated_count / total) * 300) : 0}px; background:#999;"></span> ${totals.not_evaluated_count}</div>`;
      if (totals.not_collected_users > 0) {
        div.innerHTML += `<div><em>${totals.not_collected_users} user(s) not collected for this policy</em></div>`;
      }
      container.appendChild(div);
    }
  }

  renderSummaryCards();
  renderMatrix();
  renderPolicyCharts();
</script>
</body>
</html>
```

- [ ] **Step 2: Write the failing tests**

```python
# tests/test_report_renderer.py
import json
import os
import tempfile

from report_renderer import render_report, write_report
from aggregate import aggregate_user_policy_matrix

USERS = [{"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com"}]
POLICIES = [{"id": "p1", "displayName": "Require MFA (report-only)", "state": "enabledForReportingButNotEnforced"}]
TEMPLATE_PATH = "templates/report.html"


def _matrix_result():
    signins_by_user = {"u1": [{
        "createdDateTime": "2026-08-01T10:00:00Z",
        "appDisplayName": "Office 365",
        "location": {"city": "Cairo", "countryOrRegion": "EG"},
        "deviceDetail": {"isCompliant": True},
        "appliedConditionalAccessPolicies": [{"id": "p1", "result": "reportOnlySuccess"}],
    }]}
    return aggregate_user_policy_matrix(USERS, POLICIES, signins_by_user, {})


def test_render_report_embeds_valid_json_with_matrix_data():
    matrix_result = _matrix_result()
    meta = {"total_signins": 1, "requested_days": 30, "actual_days_covered": 30}
    html = render_report(matrix_result, USERS, POLICIES, meta, TEMPLATE_PATH)

    assert "__REPORT_DATA__" not in html  # placeholder must be substituted
    start = html.index("const REPORT_DATA = ") + len("const REPORT_DATA = ")
    end = html.index(";\n", start)
    embedded = json.loads(html[start:end])

    assert embedded["users"] == USERS
    assert embedded["policies"] == POLICIES
    assert embedded["meta"] == meta
    assert embedded["matrix"]["u1"]["p1"]["counts"] == {"reportOnlySuccess": 1}
    assert "policy_totals" in embedded
    assert embedded["policy_totals"]["p1"]["counts"] == {"reportOnlySuccess": 1}


def test_render_report_escapes_script_closing_tag_in_display_names():
    tricky_users = [{"id": "u1", "displayName": "Alice</script><script>alert(1)</script>",
                      "userPrincipalName": "alice@contoso.com"}]
    matrix_result = aggregate_user_policy_matrix(tricky_users, POLICIES, {}, {})
    html = render_report(matrix_result, tricky_users, POLICIES,
                          {"total_signins": 0, "requested_days": 30, "actual_days_covered": 30},
                          TEMPLATE_PATH)
    assert "</script><script>alert(1)</script>" not in html
    assert "<\\/script>" in html


def test_write_report_writes_html_to_disk():
    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = os.path.join(tmp_dir, "report.html")
        write_report("<html>test</html>", output_path)
        with open(output_path, "r", encoding="utf-8") as f:
            assert f.read() == "<html>test</html>"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_report_renderer.py -v`
Expected: FAIL — `report_renderer` module does not exist yet.

- [ ] **Step 4: Write minimal implementation**

```python
# report_renderer.py
"""Renders the final self-contained static HTML report."""
import json

from aggregate import aggregate_policy_totals


def render_report(matrix_result: dict, users: list[dict], policies: list[dict],
                   meta: dict, template_path: str) -> str:
    matrix = matrix_result["matrix"]
    policy_totals = {
        policy["id"]: aggregate_policy_totals(matrix, policy["id"])
        for policy in policies
    }

    embedded = {
        "users": users,
        "policies": policies,
        "matrix": matrix,
        "policy_totals": policy_totals,
        "meta": meta,
    }
    # Escape a literal "</script>" inside embedded data so it can never
    # prematurely close the report's own <script> block.
    embedded_json = json.dumps(embedded).replace("</script>", "<\\/script>")

    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()

    return template.replace("__REPORT_DATA__", embedded_json)


def write_report(html: str, output_path: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_report_renderer.py -v`
Expected: PASS (all tests)

- [ ] **Step 6: Commit**

```bash
git add templates/report.html report_renderer.py tests/test_report_renderer.py
git commit -m "Add static HTML report renderer with matrix, charts, and drill-down"
```

---

### Task 10: CLI orchestration + README

**Files:**
- Create: `analyzer.py`
- Create: `README.md`
- Test: `tests/test_analyzer.py`

**Interfaces:**
- Consumes: everything from Tasks 1-9
  (`DeviceCodeAuthenticator`, `fetch_ca_policies`/`fetch_users`/`fetch_groups`/
  `fetch_group_members`/`fetch_signins_for_user`/`fetch_signins_all`, `GraphPermissionError`,
  `resolve_user_scope`, `run_selection_server`, `aggregate_user_policy_matrix`,
  `render_report`, `write_report`)
- Produces: `analyzer.run_pipeline(authenticator, session, open_browser=True, output_path="ca-report-only-analysis.html") -> str`
  (returns the output file path), `analyzer.main()` CLI entry point.

- [ ] **Step 1: Write the failing integration test (fully mocked — no live tenant)**

```python
# tests/test_analyzer.py
import os
import tempfile
from unittest.mock import MagicMock, patch

from analyzer import run_pipeline

CA_POLICIES = [
    {"id": "p1", "displayName": "Require MFA (report-only)", "state": "enabledForReportingButNotEnforced"},
    {"id": "p2", "displayName": "Block Legacy Auth", "state": "disabled"},
]
USERS = [{"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com"}]
GROUPS = []

SIGNIN = {
    "createdDateTime": "2026-08-01T10:00:00Z",
    "appDisplayName": "Office 365",
    "location": {"city": "Cairo", "countryOrRegion": "EG"},
    "deviceDetail": {"isCompliant": True},
    "userPrincipalName": "alice@contoso.com",
    "appliedConditionalAccessPolicies": [{"id": "p1", "result": "reportOnlySuccess"}],
}


@patch("analyzer.fetch_signins_all", return_value=[SIGNIN])
@patch("analyzer.run_selection_server")
@patch("analyzer.fetch_groups", return_value=GROUPS)
@patch("analyzer.fetch_users", return_value=USERS)
@patch("analyzer.fetch_ca_policies", return_value=CA_POLICIES)
def test_run_pipeline_produces_report_with_disabled_policies_excluded(
    mock_fetch_ca, mock_fetch_users, mock_fetch_groups, mock_selection_server, mock_fetch_signins
):
    mock_selection_server.return_value = {
        "all_users": True, "user_ids": [], "group_ids": [], "policy_ids": ["p1"], "days": 30,
    }
    mock_authenticator = MagicMock()
    mock_authenticator.acquire_token.return_value = "fake-token"
    mock_session = MagicMock()

    with tempfile.TemporaryDirectory() as tmp_dir:
        output_path = os.path.join(tmp_dir, "report.html")
        result_path = run_pipeline(mock_authenticator, mock_session, open_browser=False, output_path=output_path)

        assert result_path == output_path
        assert os.path.exists(output_path)
        with open(output_path, "r", encoding="utf-8") as f:
            html = f.read()
        assert "Require MFA (report-only)" in html
        assert "Block Legacy Auth" not in html  # disabled policy excluded from picker/report

    # picker only ever sees non-disabled policies
    picker_policies = mock_selection_server.call_args.kwargs.get("policies") or mock_selection_server.call_args[0][2]
    assert all(p["state"] != "disabled" for p in picker_policies)


@patch("analyzer.run_selection_server")
@patch("analyzer.fetch_groups", return_value=GROUPS)
@patch("analyzer.fetch_users", return_value=USERS)
@patch("analyzer.fetch_ca_policies", return_value=CA_POLICIES)
def test_run_pipeline_marks_user_not_collected_on_permission_error(
    mock_fetch_ca, mock_fetch_users, mock_fetch_groups, mock_selection_server
):
    from graph_client import GraphPermissionError

    mock_selection_server.return_value = {
        "all_users": True, "user_ids": [], "group_ids": [], "policy_ids": ["p1"], "days": 30,
    }
    mock_authenticator = MagicMock()
    mock_authenticator.acquire_token.return_value = "fake-token"

    with patch("analyzer.fetch_signins_all", side_effect=GraphPermissionError("403 on bulk sign-in pull")):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = os.path.join(tmp_dir, "report.html")
            run_pipeline(MagicMock(acquire_token=lambda: "tok"), MagicMock(),
                         open_browser=False, output_path=output_path)
            with open(output_path, "r", encoding="utf-8") as f:
                html = f.read()
            # A failed bulk pull must mark every scoped user "not collected" —
            # never crash uncaught, and never render as a fabricated zero.
            assert "cell-not-collected" in html
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_analyzer.py -v`
Expected: FAIL — `analyzer` module does not exist yet.

- [ ] **Step 3: Write minimal implementation**

```python
# analyzer.py
"""Entry point: wires auth, discovery, the selection server, sign-in
collection, aggregation, and report rendering together.
"""
import sys
from datetime import datetime, timedelta, timezone

import requests

from graph_client import (
    DeviceCodeAuthenticator, GraphPermissionError,
    fetch_ca_policies, fetch_users, fetch_groups, fetch_group_members,
    fetch_signins_for_user, fetch_signins_all,
)
from pipeline import resolve_user_scope
from selection_server import run_selection_server
from aggregate import aggregate_user_policy_matrix
from report_renderer import render_report, write_report

PICKER_TEMPLATE = "templates/picker.html"
REPORT_TEMPLATE = "templates/report.html"


def run_pipeline(authenticator, session, open_browser: bool = True,
                  output_path: str = "ca-report-only-analysis.html") -> str:
    # Phase A — auth + discovery
    token = authenticator.acquire_token()
    headers = {"Authorization": f"Bearer {token}"}

    all_policies = fetch_ca_policies(session, headers)
    selectable_policies = [p for p in all_policies if p.get("state") != "disabled"]
    users = fetch_users(session, headers)
    groups = fetch_groups(session, headers)

    # Phase B — scoping
    selection = run_selection_server(users, groups, selectable_policies, PICKER_TEMPLATE, open_browser=open_browser)

    def _fetch_members(group_id: str):
        return fetch_group_members(session, headers, group_id)

    scoped_users = resolve_user_scope(selection, users, _fetch_members)
    selected_policy_ids = set(selection["policy_ids"])
    report_policies = [p for p in selectable_policies if p["id"] in selected_policy_ids]

    # Phase C — collection
    since_iso = (datetime.now(timezone.utc) - timedelta(days=selection["days"])).strftime("%Y-%m-%dT%H:%M:%SZ")
    signins_by_user: dict[str, list[dict]] = {}
    collection_errors: dict[str, str] = {}

    if selection.get("all_users"):
        try:
            all_signins = fetch_signins_all(session, headers, since_iso)
        except GraphPermissionError as exc:
            # The bulk pull covers every scoped user in one call, so a
            # failure here means none of them were collected — mark all of
            # them, never let it crash the whole report uncaught, and never
            # let a failed pull look like a genuine empty result.
            for user in scoped_users:
                collection_errors[user["id"]] = str(exc)
        else:
            for signin in all_signins:
                upn = signin.get("userPrincipalName")
                user_id = next((u["id"] for u in scoped_users if u.get("userPrincipalName") == upn), None)
                if user_id:
                    signins_by_user.setdefault(user_id, []).append(signin)
    else:
        for user in scoped_users:
            try:
                signins_by_user[user["id"]] = fetch_signins_for_user(
                    session, headers, user["userPrincipalName"], since_iso
                )
            except GraphPermissionError as exc:
                collection_errors[user["id"]] = str(exc)

    matrix_result = aggregate_user_policy_matrix(scoped_users, report_policies, signins_by_user, collection_errors)

    total_signins = sum(len(v) for v in signins_by_user.values())
    meta = {
        "total_signins": total_signins,
        "requested_days": selection["days"],
        "actual_days_covered": min(selection["days"], 30),
    }

    html = render_report(matrix_result, scoped_users, report_policies, meta, REPORT_TEMPLATE)
    write_report(html, output_path)
    return output_path


def main() -> None:
    authenticator = DeviceCodeAuthenticator()
    session = requests.Session()
    output_path = run_pipeline(authenticator, session)
    print(f"Report written to {output_path}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_analyzer.py -v`
Expected: PASS (both tests)

- [ ] **Step 5: Run the full test suite**

Run: `pytest -v`
Expected: PASS (all tests across all modules)

- [ ] **Step 6: Write README.md**

```markdown
# CA Report-Only Policy Analyzer

A standalone tool that answers: for a chosen set of users over a chosen time window,
which Entra ID Conditional Access policies currently in **report-only** mode would
actually have applied — and to what effect?

It reads real sign-in log events and their own `appliedConditionalAccessPolicies[]`
evaluation results — it never infers or simulates a policy's behavior.

## Usage

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python analyzer.py
```

You'll be prompted with a device code to sign in with. Once signed in, your default
browser opens to a page where you pick which users (or groups, or all users), which
report-only policies, and how many days back to analyze. Submitting that page starts
the sign-in log pull; when it finishes, a report opens automatically as
`ca-report-only-analysis.html` in the current directory.

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
  will return fewer days than requested, and the report shows the actual range
  covered separately from what you asked for.
- A missing policy entry on a sign-in event means Conditional Access did not
  evaluate that policy for that request — it is shown as "not evaluated," which is
  never the same thing as "would not apply."
```

- [ ] **Step 7: Commit**

```bash
git add analyzer.py README.md tests/test_analyzer.py
git commit -m "Add CLI orchestration wiring auth, scoping, collection, and reporting"
```

---

## Self-Review Notes

- **Spec coverage:** Auth (Task 4), discovery + pagination/backoff (Tasks 5-6), the
  three-state aggregation model (Tasks 2-3), scope resolution incl. group expansion
  (Task 7), the transient picker server (Task 8), the static report with matrix/bar
  chart/drill-down and caveats section (Task 9), and end-to-end wiring + README
  (Task 10) all map directly to spec sections. Disabled-policy exclusion from the
  picker (spec Phase A) is asserted directly in Task 10's test.
- **Type consistency:** `cell` shape (`not_collected`, `counts`, `not_evaluated_count`,
  `total_signins`, `sample_events`) is defined once in Task 2 and reused unchanged by
  Tasks 3, 9, and 10 — no renamed fields across tasks. `selection` dict shape
  (`all_users`, `user_ids`, `group_ids`, `policy_ids`, `days`) is defined in Task 8's
  picker JS/server contract and consumed identically by Task 7 (`resolve_user_scope`)
  and Task 10 (`run_pipeline`).
- **Sandbox limitation stated up front, not assumed away**: the Global Constraints
  section and every task's "Expected" lines describe unit/mocked-integration test
  results only — no task claims live-tenant or live-browser verification.

## Deferred Past v1 (per spec)

- Workload-identity/service-principal sign-in analysis.
- Any write/promote-to-enforced action.
