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


@patch("analyzer.run_selection_server")
@patch("analyzer.fetch_groups", return_value=GROUPS)
@patch("analyzer.fetch_users", return_value=USERS)
@patch("analyzer.fetch_ca_policies", return_value=CA_POLICIES)
def test_run_pipeline_marks_user_not_collected_on_throttled_error_bulk(
    mock_fetch_ca, mock_fetch_users, mock_fetch_groups, mock_selection_server
):
    from graph_client import GraphThrottledError

    mock_selection_server.return_value = {
        "all_users": True, "user_ids": [], "group_ids": [], "policy_ids": ["p1"], "days": 30,
    }

    with patch("analyzer.fetch_signins_all",
               side_effect=GraphThrottledError("429 retries exhausted on bulk sign-in pull")):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = os.path.join(tmp_dir, "report.html")
            # Must not raise uncaught, and must not discard already-collected data.
            run_pipeline(MagicMock(acquire_token=lambda: "tok"), MagicMock(),
                         open_browser=False, output_path=output_path)
            with open(output_path, "r", encoding="utf-8") as f:
                html = f.read()
            assert "cell-not-collected" in html


@patch("analyzer.run_selection_server")
@patch("analyzer.fetch_groups", return_value=GROUPS)
@patch("analyzer.fetch_users", return_value=USERS)
@patch("analyzer.fetch_ca_policies", return_value=CA_POLICIES)
def test_run_pipeline_marks_user_not_collected_on_throttled_error_per_user(
    mock_fetch_ca, mock_fetch_users, mock_fetch_groups, mock_selection_server
):
    from graph_client import GraphThrottledError

    mock_selection_server.return_value = {
        "all_users": False, "user_ids": ["u1"], "group_ids": [], "policy_ids": ["p1"], "days": 30,
    }

    with patch("analyzer.fetch_signins_for_user",
               side_effect=GraphThrottledError("429 retries exhausted for alice@contoso.com")):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = os.path.join(tmp_dir, "report.html")
            run_pipeline(MagicMock(acquire_token=lambda: "tok"), MagicMock(),
                         open_browser=False, output_path=output_path)
            with open(output_path, "r", encoding="utf-8") as f:
                html = f.read()
            assert "cell-not-collected" in html
