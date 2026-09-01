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
