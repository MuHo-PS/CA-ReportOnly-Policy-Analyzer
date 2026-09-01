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
