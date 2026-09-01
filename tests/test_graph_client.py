from unittest.mock import MagicMock, patch, call

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


import pytest
import requests  # noqa: E402

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
