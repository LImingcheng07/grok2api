#!/usr/bin/env python3
"""HTTP sidecar for grok2api auto account refill.

POST /v1/register
{
  "proxy": "http://user:pass@host:port",   // optional; one IP per job
  "config": { ... mail/captcha settings ... }
}

GET /healthz
"""

from __future__ import annotations

import json
import os
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

from protocol_register import register_one


def _json_response(handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class Handler(BaseHTTPRequestHandler):
    server_version = "grok2api-auto-register/1.0"

    def log_message(self, fmt: str, *args: Any) -> None:
        print(f"[auto-register] {self.address_string()} {fmt % args}", flush=True)

    def do_GET(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path in {"/healthz", "/health", "/"}:
            _json_response(self, 200, {"ok": True, "service": "auto-register"})
            return
        _json_response(self, 404, {"ok": False, "error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = urlparse(self.path).path
        if path not in {"/v1/register", "/register"}:
            _json_response(self, 404, {"ok": False, "error": "not found"})
            return
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0 or length > 1 << 20:
            _json_response(self, 400, {"ok": False, "error": "invalid body size"})
            return
        try:
            raw = self.rfile.read(length)
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            _json_response(self, 400, {"ok": False, "error": "invalid json"})
            return
        if not isinstance(payload, dict):
            _json_response(self, 400, {"ok": False, "error": "body must be object"})
            return

        config = payload.get("config") if isinstance(payload.get("config"), dict) else payload
        proxy = str(payload.get("proxy") or config.get("proxy") or "").strip()
        index = int(payload.get("index") or 1)
        logs: list[str] = []

        def emit(message: str) -> None:
            logs.append(message)
            print(message, flush=True)

        try:
            result = register_one(dict(config), proxy=proxy, log=emit, index=index)
            result["logs"] = logs[-80:]
            # Surface last structured phase for the Go status UI.
            phase = "done"
            for line in reversed(logs):
                if "[phase:" in line:
                    try:
                        phase = line.split("[phase:", 1)[1].split("]", 1)[0]
                    except Exception:
                        phase = "done"
                    break
            result["phase"] = phase
            result["progress"] = logs[-1] if logs else ""
            _json_response(self, 200, result)
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            phase = "failed"
            for line in reversed(logs):
                if "[phase:" in line:
                    try:
                        phase = line.split("[phase:", 1)[1].split("]", 1)[0]
                    except Exception:
                        pass
                    break
            _json_response(
                self,
                500,
                {
                    "ok": False,
                    "error": str(exc)[:500],
                    "logs": logs[-80:],
                    "phase": phase,
                    "progress": logs[-1] if logs else str(exc)[:200],
                },
            )


def main() -> None:
    host = os.environ.get("AUTO_REGISTER_HOST", "0.0.0.0")
    port = int(os.environ.get("AUTO_REGISTER_PORT", "8091"))
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"[auto-register] listening on {host}:{port}", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
