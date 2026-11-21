"""HTTP API and static files for the dashboard. Standard library only.

- listens on 127.0.0.1 only
- requests with a non-localhost Host header are rejected (DNS rebinding)
- POSTs need the token from data/.token in an X-SIEM-Token header
- static files are served from a fixed list, no path lookups
"""
from __future__ import annotations

import json
import logging
import secrets
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .rules import FIELDS, FUNCS, SEVERITIES, RuleError

log = logging.getLogger("siem.http")

STATIC = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
    "/countries.js": ("countries.js", "text/javascript; charset=utf-8"),
}
CSP = ("default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; "
       "style-src 'self' 'unsafe-inline'; connect-src 'self' https://cdn.jsdelivr.net; "
       "img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; "
       "form-action 'none'")
MAX_BODY = 512 * 1024


def make_server(engine, root: Path, host: str, port: int) -> ThreadingHTTPServer:
    # keep the token across restarts so open tabs don't break
    tok_file = root / "data" / ".token"
    try:
        token = tok_file.read_text().strip()
    except OSError:
        token = ""
    if len(token) < 24:
        token = secrets.token_urlsafe(24)
        tok_file.touch(mode=0o600)
        tok_file.write_text(token)
    tok_file.chmod(0o600)
    static_dir = root / "static"
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}

    class Handler(BaseHTTPRequestHandler):
        server_version = "mac-siem"
        sys_version = ""

        def log_message(self, fmt, *args):
            log.debug("%s - %s", self.address_string(), fmt % args)

        # helpers
        def _headers(self, status: int, ctype: str, length: int):
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Cross-Origin-Opener-Policy", "same-origin")
            self.send_header("Cross-Origin-Resource-Policy", "same-origin")
            self.send_header("Content-Security-Policy", CSP)
            self.end_headers()

        def _json(self, obj, status: int = 200):
            body = json.dumps(obj, default=str, separators=(",", ":")).encode()
            self._headers(status, "application/json", len(body))
            self.wfile.write(body)

        def _err(self, status: int, msg: str):
            self._json({"error": msg}, status)

        def _host_ok(self) -> bool:
            if self.headers.get("Host", "") not in allowed_hosts:
                self._err(HTTPStatus.MISDIRECTED_REQUEST, "bad host")
                return False
            return True

        def _body(self) -> dict | None:
            if not secrets.compare_digest(self.headers.get("X-SIEM-Token", "").encode(),
                                          token.encode()):
                self._err(HTTPStatus.FORBIDDEN, "missing or bad token")
                return None
            if not self.headers.get("Content-Type", "").startswith("application/json"):
                self._err(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "expected application/json")
                return None
            try:
                n = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                n = -1
            if n < 0 or n > MAX_BODY:
                self._err(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "body too large")
                return None
            try:
                data = json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                self._err(HTTPStatus.BAD_REQUEST, "invalid JSON")
                return None
            if not isinstance(data, dict):
                self._err(HTTPStatus.BAD_REQUEST, "expected a JSON object")
                return None
            return data

        # GET
        def do_GET(self):
            if not self._host_ok():
                return
            u = urlparse(self.path)
            q = {k: v[-1] for k, v in parse_qs(u.query).items()}
            if u.path in STATIC:
                name, ctype = STATIC[u.path]
                try:
                    data = (static_dir / name).read_bytes()
                except OSError:
                    return self._err(404, "not found")
                if name == "index.html":
                    data = data.replace(b"__SIEM_TOKEN__", token.encode())
                self._headers(200, ctype, len(data))
                self.wfile.write(data)
                return
            try:
                if u.path == "/api/snapshot":
                    return self._json(engine.snapshot())
                if u.path == "/api/alerts":
                    return self._json(engine.store.alerts(
                        limit=int(q.get("limit", 300)), include_acked=q.get("acked", "1") == "1"))
                if u.path == "/api/events":
                    since = time.time() - float(q.get("hours", 24)) * 3600
                    return self._json(engine.store.search_events(
                        q.get("q", "")[:200], q.get("kind", ""), since, int(q.get("limit", 500))))
                if u.path == "/api/history":
                    since = time.time() - float(q.get("hours", 24)) * 3600
                    return self._json(engine.store.top_history(since))
                if u.path == "/api/rules":
                    return self._json({
                        "text": engine.rules.text(), "error": engine.rules.error,
                        "fields": FIELDS, "functions": list(FUNCS), "severities": SEVERITIES,
                        "rules": [{"id": r.id, "name": r.name, "severity": r.severity,
                                   "enabled": r.enabled, "condition": r.condition}
                                  for r in engine.rules.rules]})
            except ValueError:
                return self._err(400, "bad parameter")
            self._err(404, "not found")

        # POST
        def do_POST(self):
            if not self._host_ok():
                return
            data = self._body()
            if data is None:
                return
            path = urlparse(self.path).path
            if path == "/api/rules":
                text = data.get("text")
                if not isinstance(text, str) or len(text) > MAX_BODY:
                    return self._err(400, "text required")
                try:
                    rules = engine.rules.save(text)
                except RuleError as e:
                    return self._json({"ok": False, "error": str(e)}, 422)
                return self._json({"ok": True, "count": len(rules)})
            if path == "/api/rules/test":
                try:
                    hits = engine.test_condition(str(data.get("condition", "")))
                except RuleError as e:
                    return self._json({"ok": False, "error": str(e)}, 422)
                return self._json({"ok": True, "matches": hits[:500], "count": len(hits)})
            if path == "/api/alerts/ack":
                ids = data.get("ids")
                if ids != "all" and not isinstance(ids, list):
                    return self._err(400, "ids must be a list or 'all'")
                try:
                    n = engine.store.ack(None if ids == "all" else ids)
                except (TypeError, ValueError):
                    return self._err(400, "ids must be integers")
                return self._json({"ok": True, "acked": n})
            if path == "/api/pause":
                engine.paused = bool(data.get("paused"))
                return self._json({"ok": True, "paused": engine.paused})
            self._err(404, "not found")

        def do_PUT(self):
            self._err(405, "method not allowed")

        do_DELETE = do_PATCH = do_PUT

    return ThreadingHTTPServer((host, port), Handler)
