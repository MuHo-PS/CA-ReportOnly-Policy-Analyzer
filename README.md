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
