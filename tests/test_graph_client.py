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
