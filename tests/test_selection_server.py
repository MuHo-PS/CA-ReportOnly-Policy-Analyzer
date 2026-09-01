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
