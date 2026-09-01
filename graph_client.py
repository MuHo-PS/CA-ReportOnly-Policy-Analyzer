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
