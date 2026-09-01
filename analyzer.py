"""Entry point: wires auth, discovery, the selection server, sign-in
collection, aggregation, and report rendering together.
"""
import sys
from datetime import datetime, timedelta, timezone

import requests

from graph_client import (
    DeviceCodeAuthenticator, GraphPermissionError, GraphThrottledError,
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
        except (GraphPermissionError, GraphThrottledError, requests.HTTPError) as exc:
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
            except (GraphPermissionError, GraphThrottledError, requests.HTTPError) as exc:
                collection_errors[user["id"]] = str(exc)

    matrix_result = aggregate_user_policy_matrix(scoped_users, report_policies, signins_by_user, collection_errors)

    total_signins = sum(len(v) for v in signins_by_user.values())
    meta = {
        "total_signins": total_signins,
        "requested_days": selection["days"],
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
