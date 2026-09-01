"""Transient loopback-only HTTP server for the scope-selection picker page.

Exists only for the duration of one selection round-trip: serve the
picker page with data embedded, receive one POST /submit, then shut
itself down and hand the parsed selection back to the caller.
"""
import json
import threading
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _render_picker_html(template_path: str, users: list[dict], groups: list[dict], policies: list[dict]) -> str:
    with open(template_path, "r", encoding="utf-8") as f:
        template = f.read()
    return (
        template
        .replace("__USERS_JSON__", json.dumps(users))
        .replace("__GROUPS_JSON__", json.dumps(groups))
        .replace("__POLICIES_JSON__", json.dumps(policies))
    )


def run_selection_server(
    users: list[dict], groups: list[dict], policies: list[dict],
    template_path: str, open_browser: bool = True,
) -> dict:
    page_html = _render_picker_html(template_path, users, groups, policies)
    result: dict = {}
    submitted = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format, *args):
            pass  # keep test/CLI output quiet

        def do_GET(self):
            if self.path in ("/", "/index.html"):
                body = page_html.encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path != "/submit":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            raw_body = self.rfile.read(length)
            try:
                payload = json.loads(raw_body)
            except json.JSONDecodeError:
                self.send_response(400)
                self.end_headers()
                return
            result["selection"] = payload
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"status":"ok"}')
            submitted.set()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    url = f"http://127.0.0.1:{port}/"
    if open_browser:
        webbrowser.open(url)

    submitted.wait()
    server.shutdown()
    server_thread.join(timeout=5)

    return result["selection"]
