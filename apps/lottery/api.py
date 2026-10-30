#!/usr/bin/env python3
"""Reference HTTP API for the anti-duplicate collaborative search pool.

This is the clean, dependency-free implementation of the protocol described in
``AGENT_SKILL.md``: register an agent, lease a guaranteed-free block, close it,
submit tested scalars, read stats.  Everything is backed by
:class:`sqflab.registry.Registry` (SQLite + WAL), so a crash never loses a
lease and no two agents can ever work on the same interval.

    python3 apps/lottery/api.py --host 0.0.0.0 --port 8000 --db pool.sqlite3

The original single-file monolith with the 83-key funnel and the browser
dashboard is preserved as ``server_legacy.py``.
"""

from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from sqflab.registry import Registry  # noqa: E402

INDEX_HTML = """<!doctype html>
<meta charset="utf-8"><title>sqf-lab pool</title>
<style>body{font:14px/1.5 ui-monospace,monospace;margin:2rem;max-width:60rem}</style>
<h1>sqf-lab anti-duplicate pool</h1>
<p>Protocol: <code>POST /api/agents/register</code> &rarr; <code>POST /api/ranges/claim</code>
&rarr; <code>POST /api/ranges/complete</code>. State: <code>GET /api/state</code>.</p>
<pre id="state">loading…</pre>
<script>
fetch('/api/state').then(r=>r.json()).then(j=>{document.getElementById('state').textContent=JSON.stringify(j,null,2)});
</script>
"""


class PoolHandler(BaseHTTPRequestHandler):
    registry: Registry
    server_version = "sqf-lab-pool/0.1"

    # -- plumbing ---------------------------------------------------------- #
    def log_message(self, fmt: str, *args: Any) -> None:  # quieter default
        if self.server.verbose:  # type: ignore[attr-defined]
            super().log_message(fmt, *args)

    def _send(self, payload: Any, status: int = 200) -> None:
        body = json.dumps(payload, indent=2).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        return json.loads(self.rfile.read(length) or b"{}")

    # -- routes ------------------------------------------------------------ #
    def do_OPTIONS(self) -> None:  # noqa: N802
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            body = INDEX_HTML.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if parsed.path in ("/api/state", "/api/stats"):
            label = (parse_qs(parsed.query).get("label") or [None])[0]
            self._send(self.registry.stats(label))
            return
        self._send({"error": "not found"}, 404)

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            self._send({"error": "invalid json"}, 400)
            return

        if parsed.path == "/api/agents/register":
            agent = self.registry.register_agent(
                payload.get("name") or "anonymous",
                model_family=payload.get("model_family", ""),
                strategy=payload.get("strategy", ""),
            )
            self._send({"agent_id": agent, "ok": True})
            return

        if parsed.path == "/api/ranges/claim":
            try:
                block = self.registry.claim(
                    payload.get("label") or "puzzle-140",
                    agent_id=payload.get("agent_id"),
                    bits=payload.get("bits"),
                    span=payload.get("span"),
                    start=_as_int(payload.get("start_k_hex") or payload.get("start_k")),
                    end=_as_int(payload.get("end_k_hex") or payload.get("end_k")),
                )
            except (ValueError, RuntimeError) as exc:
                self._send({"ok": False, "error": str(exc)}, 409)
                return
            self._send({"ok": True, **block})
            return

        if parsed.path == "/api/ranges/complete":
            try:
                block = self.registry.complete(
                    payload["block_id"], ops=int(payload.get("ops") or 0)
                )
            except KeyError:
                self._send({"ok": False, "error": "unknown block_id"}, 404)
                return
            self._send({"ok": True, **block})
            return

        if parsed.path == "/api/submit/key":
            value = _as_int(payload.get("k") or payload.get("k_hex"))
            if value is None:
                self._send({"ok": False, "error": "k required"}, 400)
                return
            inserted = self.registry.submit_key(
                value,
                bits=value.bit_length(),
                agent_id=payload.get("agent_id"),
                source=payload.get("source", "api"),
            )
            self._send({"ok": True, "stored": inserted, "duplicate": not inserted})
            return

        if parsed.path == "/api/submit/dp":
            inserted = self.registry.submit_dp(
                payload.get("label") or "puzzle-140",
                payload["tag"],
                int(payload.get("herd") or 0),
                int(payload.get("distance") or 0),
                payload.get("x_tag", ""),
            )
            self._send({"ok": True, "stored": inserted})
            return

        self._send({"error": "not found"}, 404)


def _as_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    if isinstance(value, int):
        return value
    text = str(value).strip().lower()
    return int(text, 16) if text.startswith("0x") else int(text)


def serve(host: str = "0.0.0.0", port: int = 8000, db: str = "pool.sqlite3",
          verbose: bool = False) -> ThreadingHTTPServer:
    """Create (but do not start) the HTTP server; useful for tests."""
    registry = Registry(db)
    handler = type("BoundPoolHandler", (PoolHandler,), {"registry": registry})
    httpd = ThreadingHTTPServer((host, port), handler)
    httpd.verbose = verbose  # type: ignore[attr-defined]
    httpd.registry = registry  # type: ignore[attr-defined]
    return httpd


def main(argv: Optional[list] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--db", default="pool.sqlite3")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)

    httpd = serve(args.host, args.port, args.db, args.verbose)
    print(f"pool API on http://{args.host}:{args.port}  (db={args.db})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
        httpd.registry.close()  # type: ignore[attr-defined]
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
