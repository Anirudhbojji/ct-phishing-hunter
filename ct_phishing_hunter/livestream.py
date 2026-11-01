"""Optional live mode: consume a certstream-compatible WebSocket feed.

The original public certstream server (certstream.calidog.io) has been shut
down, so this mode expects a self-hosted endpoint, e.g.
https://github.com/d-Rickyy-b/certstream-server-go
"""

import json
import time
from collections.abc import Iterator

import websocket

RECONNECT_DELAY_SECONDS = 5


def stream_cert_domains(server_url: str) -> Iterator[list[str]]:
    """Yield the domain list of every certificate seen on the feed."""
    ws: websocket.WebSocket | None = None
    while True:
        try:
            if ws is None:
                ws = websocket.create_connection(server_url, timeout=90)
            msg = json.loads(ws.recv())
            if msg.get("message_type") != "certificate_update":
                continue
            domains = msg.get("data", {}).get("leaf_cert", {}).get("all_domains", [])
            if domains:
                yield domains
        except (websocket.WebSocketException, ConnectionError, TimeoutError, OSError):
            if ws is not None:
                ws.close()
                ws = None
            time.sleep(RECONNECT_DELAY_SECONDS)
