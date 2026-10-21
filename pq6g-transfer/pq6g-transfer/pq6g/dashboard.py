"""Tiny stdlib HTTP server: serves the dashboard page and streams events (SSE).

Works on a laptop and on a phone (Termux) with no extra packages.  Bind to
0.0.0.0 to watch from another device on the same Wi-Fi.
"""
from __future__ import annotations

import json
import os
import queue
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PAGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web", "dashboard.html")


def page_html() -> str:
    # works from a zip/pyz as well as from a folder
    try:
        with open(PAGE, encoding="utf-8") as f:
            return f.read()
    except OSError:
        import pkgutil
        return pkgutil.get_data(__name__.rsplit(".", 1)[0], "web/dashboard.html").decode("utf-8")


def phone_html() -> str:
    path = os.path.join(os.path.dirname(PAGE), "phone.html")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read()
    except OSError:
        import pkgutil
        return pkgutil.get_data(__name__.rsplit(".", 1)[0], "web/phone.html").decode("utf-8")


class _Handler(BaseHTTPRequestHandler):
    server_version = "pq6g"

    def log_message(self, *a):          # keep the terminal clean
        pass

    def _send(self, code, ctype, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            self._send(200, "text/html; charset=utf-8", page_html().encode("utf-8"))
        elif path == "/phone":
            self._send(200, "text/html; charset=utf-8", phone_html().encode("utf-8"))
        elif path == "/file":
            done = [e for e in self.server.events.events if e.get("ev") == "file_verified"]
            fp = done[-1].get("path") if done else None
            if not fp or not os.path.isfile(fp):
                return self._send(404, "text/plain", b"no verified file yet")
            name = os.path.basename(fp)
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(os.path.getsize(fp)))
            self.send_header("Content-Disposition", 'attachment; filename="%s"' % name.replace('"', ""))
            self.end_headers()
            with open(fp, "rb") as f:
                while True:
                    b = f.read(1 << 20)
                    if not b:
                        break
                    self.wfile.write(b)
        elif path in ("/api/quantum/noise", "/api/quantum/image"):
            g = getattr(self.server, "guide", None)
            try:
                i = int(self.path.partition("job=")[2].split("&")[0])
            except ValueError:
                i = -1
            if g is None:
                return self._send(404, "text/plain", b"no guide")
            if path.endswith("noise"):
                b = g.job_noise(i)
                return self._send(200, "application/octet-stream", b) if b else self._send(404, "text/plain", b"none")
            im = g.job_image(i)
            if not im:
                return self._send(404, "text/plain", b"none")
            with open(im[0], "rb") as f:
                return self._send(200, im[1], f.read())
        elif path == "/api/run":
            st = getattr(self.server, "studio", None)
            self._send(200, "application/json", json.dumps(st.info() if st else {"run": 0, "file": None, "studio": False}).encode())
        elif path == "/api/guide":
            g = getattr(self.server, "guide", None)
            self._send(200, "application/json", json.dumps(g.state() if g else {"steps": []}).encode())
        elif path == "/api/caps":
            link = self.server.link
            self._send(200, "application/json", json.dumps({"cut": link is not None, "tamper": link is not None}).encode())
        elif path == "/events":
            self._stream()
        else:
            self._send(404, "text/plain", b"not found")

    def do_POST(self):
        st = getattr(self.server, "studio", None)
        if st is not None and self.path.startswith("/api/upload"):
            from urllib.parse import urlparse, parse_qs, unquote
            q = parse_qs(urlparse(self.path).query)
            name = unquote(q.get("name", ["file.bin"])[0])
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length <= 0:
                return self._send(400, "text/plain", b"empty file")
            path = st.save_upload(name, self.rfile, length)
            ok = st.choose(path)
            return self._send(200 if ok else 409, "application/json", json.dumps({"ok": ok}).encode())
        if st is not None and self.path.startswith("/api/sample"):
            return self._send(200, "application/json", json.dumps({"ok": st.sample()}).encode())
        if st is not None and self.path.startswith("/api/reset"):
            return self._send(200, "application/json", json.dumps(st.reset()).encode())
        link = self.server.link
        g = getattr(self.server, "guide", None)
        if g is not None and self.path.startswith("/api/guide/next"):
            return self._send(200, "application/json", json.dumps({"ok": g.next()}).encode())
        if g is not None and self.path.startswith("/api/guide/all"):
            return self._send(200, "application/json", json.dumps({"ok": g.run_all()}).encode())
        if link is None:
            return self._send(404, "text/plain", b"no link emulator here")
        if self.path.startswith("/api/cut"):
            ok = link.request_blockage("manual (button)")
            return self._send(200, "application/json", json.dumps({"ok": ok}).encode())
        if self.path.startswith("/api/tamper"):
            link.arm_tamper()
            return self._send(200, "application/json", b'{"ok":true}')
        self._send(404, "text/plain", b"not found")

    def _stream(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        ev0 = self.server.events
        snap, q = ev0.subscribe()
        try:
            for rec in snap:
                self.wfile.write(b"data: " + json.dumps(rec, separators=(",", ":")).encode() + b"\n\n")
            self.wfile.flush()
            while True:
                try:
                    rec = q.get(timeout=10)
                    batch = [rec]
                    while len(batch) < 400:
                        try:
                            batch.append(q.get_nowait())
                        except queue.Empty:
                            break
                    self.wfile.write(b"".join(b"data: " + json.dumps(r, separators=(",", ":")).encode() + b"\n\n"
                                              for r in batch))
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    if self.server.events is not ev0:        # a new run started: end this stream so the page reconnects
                        break
                self.wfile.flush()
        except (BrokenPipeError, ConnectionError, OSError):
            pass
        finally:
            ev0.unsubscribe(q)


class _Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(events, port: int, host: str = "0.0.0.0", link=None, guide=None):
    srv = _Server((host, port), _Handler)
    srv.events, srv.link, srv.guide = events, link, guide
    threading.Thread(target=srv.serve_forever, daemon=True, name="dashboard").start()
    return srv


def lan_ip() -> str:
    """Best-effort address other devices on the Wi-Fi can use."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"
