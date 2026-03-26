"""Browser-based authentication flow for CyberLens account connection."""

import os
import secrets
import threading
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse, parse_qs

import yaml


CONNECT_BASE_URL = "https://cyberlensai.com/connect"
CONFIG_DIR = Path.home() / ".openclaw" / "skills" / "cyberlens"
CONFIG_FILE = CONFIG_DIR / "config.yaml"


class _CallbackHandler(BaseHTTPRequestHandler):
    """Handles the localhost callback from cyberlensai.com/connect."""

    api_key: Optional[str] = None
    state: Optional[str] = None
    expected_state: Optional[str] = None
    received = threading.Event()

    def do_GET(self, *args, **kwargs):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        key = params.get("key", [None])[0]
        state = params.get("state", [None])[0]

        if key and state == self.expected_state:
            _CallbackHandler.api_key = key
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><body style='font-family:system-ui;background:#1a1a2e;color:white;"
                b"display:flex;align-items:center;justify-content:center;height:100vh;margin:0'>"
                b"<div style='text-align:center'>"
                b"<h1>&#x2705; Connected!</h1>"
                b"<p>You can close this tab and return to your terminal.</p>"
                b"</div></body></html>"
            )
        else:
            self.send_response(400)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Invalid callback. State mismatch or missing key.")

        _CallbackHandler.received.set()

    def log_message(self, format, *args):
        pass  # Suppress HTTP server logs


def _find_open_port() -> int:
    """Find an available port in the 54321-54399 range."""
    import socket
    for port in range(54321, 54400):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("127.0.0.1", port))
                return port
        except OSError:
            continue
    raise RuntimeError("No available ports in range 54321-54399")


def save_api_key(key: str) -> Path:
    """Save the API key to the skill config file."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    config = {}
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            config = yaml.safe_load(f) or {}

    config["api_key"] = key
    with open(CONFIG_FILE, "w") as f:
        yaml.dump(config, f, default_flow_style=False)

    return CONFIG_FILE


def load_api_key() -> Optional[str]:
    """Load the API key from env var or config file."""
    # Check env var first
    env_key = os.environ.get("CYBERLENS_API_KEY")
    if env_key:
        return env_key

    # Check config file
    if CONFIG_FILE.exists():
        with open(CONFIG_FILE) as f:
            config = yaml.safe_load(f) or {}
            return config.get("api_key")

    return None


async def run_connect_flow() -> str:
    """
    Run the browser-based connect flow.

    Opens cyberlensai.com/connect in the user's browser, starts a localhost
    callback server, and waits for the API key to be delivered.

    Returns the API key string.
    """
    state = secrets.token_urlsafe(32)
    port = _find_open_port()

    # Reset handler state
    _CallbackHandler.api_key = None
    _CallbackHandler.expected_state = state
    _CallbackHandler.received = threading.Event()

    # Start callback server in a thread
    server = HTTPServer(("127.0.0.1", port), _CallbackHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()

    # Open browser
    callback_url = f"http://localhost:{port}/callback"
    connect_url = (
        f"{CONNECT_BASE_URL}?client=openclaw_skill"
        f"&callback={callback_url}"
        f"&state={state}"
    )
    webbrowser.open(connect_url)

    # Wait for callback (timeout 120 seconds)
    received = _CallbackHandler.received.wait(timeout=120)
    server.shutdown()

    if not received or not _CallbackHandler.api_key:
        raise TimeoutError(
            "Did not receive API key within 120 seconds. "
            "Please try again or manually copy your key from cyberlensai.com/profile."
        )

    key = _CallbackHandler.api_key

    # Save to config
    config_path = save_api_key(key)

    return key
