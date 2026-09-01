import os
import tempfile
from unittest.mock import MagicMock, patch

import analyzer
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
        with patch("analyzer.webbrowser.open") as mock_browser_open:
            result_path = run_pipeline(mock_authenticator, mock_session, open_browser=False, output_path=output_path)
            # open_browser=False must never trigger opening the finished report.
            assert mock_browser_open.called is False

        assert result_path == output_path
        assert os.path.exists(output_path)
        with open(output_path, "r", encoding="utf-8") as f:
            html = f.read()
        assert "Require MFA (report-only)" in html
        assert "Block Legacy Auth" not in html  # disabled policy excluded from picker/report

    # picker only ever sees non-disabled policies
    picker_policies = mock_selection_server.call_args.kwargs.get("policies") or mock_selection_server.call_args[0][2]
    assert all(p["state"] != "disabled" for p in picker_policies)


@patch("analyzer.fetch_signins_all", return_value=[SIGNIN])
@patch("analyzer.run_selection_server")
@patch("analyzer.fetch_groups", return_value=GROUPS)
@patch("analyzer.fetch_users", return_value=USERS)
@patch("analyzer.fetch_ca_policies", return_value=CA_POLICIES)
def test_run_pipeline_opens_browser_on_finished_report_when_requested(
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
        with patch("analyzer.webbrowser.open") as mock_browser_open:
            result_path = run_pipeline(mock_authenticator, mock_session, open_browser=True, output_path=output_path)
            assert mock_browser_open.called is True
            (opened_url,), _ = mock_browser_open.call_args
            assert result_path in opened_url or opened_url.endswith(os.path.basename(output_path))


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
            # The report must not claim a fabricated "actual days covered"
            # number that was never actually measured from real data.
            assert "actual_days_covered" not in html


@patch("analyzer.run_selection_server")
@patch("analyzer.fetch_groups", return_value=GROUPS)
@patch("analyzer.fetch_users")
@patch("analyzer.fetch_ca_policies", return_value=CA_POLICIES)
def test_run_pipeline_summary_reflects_not_collected_users(
    mock_fetch_ca, mock_fetch_users, mock_fetch_groups, mock_selection_server
):
    from graph_client import GraphPermissionError

    two_users = [
        {"id": "u1", "displayName": "Alice", "userPrincipalName": "alice@contoso.com"},
        {"id": "u2", "displayName": "Bob", "userPrincipalName": "bob@contoso.com"},
    ]
    mock_fetch_users.return_value = two_users
    mock_selection_server.return_value = {
        "all_users": True, "user_ids": [], "group_ids": [], "policy_ids": ["p1"], "days": 30,
    }

    def fake_fetch_signins_all(session, headers, since_iso):
        raise GraphPermissionError("403 on bulk sign-in pull")

    with patch("analyzer.fetch_signins_all", side_effect=fake_fetch_signins_all):
        with tempfile.TemporaryDirectory() as tmp_dir:
            output_path = os.path.join(tmp_dir, "report.html")
            run_pipeline(MagicMock(acquire_token=lambda: "tok"), MagicMock(),
                         open_browser=False, output_path=output_path)
            with open(output_path, "r", encoding="utf-8") as f:
                html = f.read()
            # Both users are embedded in REPORT_DATA.matrix as not_collected;
            # the raw data must be present for the summary card computation.
            assert html.count('"not_collected": true') >= 2 or html.count('"not_collected":true') >= 2


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
