#!/usr/bin/env python3
"""Small network deception sensor inspired by the ideas behind T-Pot.

This is intentionally simple: it emulates a few common services, records what
connects to them, and exposes a protected monitoring dashboard.
"""

from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import secrets
import signal
import socketserver
import threading
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from uuid import uuid4


MAX_BODY_BYTES = 8192


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def truncate(value: str, limit: int = 600) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "...[truncated]"


def normalize_form_body(body: str) -> str:
    body = body.strip()
    if len(body) >= 2 and body[0] == body[-1] and body[0] in ("'", '"'):
        return body[1:-1]
    return body


class GeoResolver:
    def __init__(self, data_dir: Path, enabled: bool = False):
        self.enabled = enabled
        self.cache_path = data_dir / "geo-cache.json"
        self._lock = threading.Lock()
        self._cache = self._load_cache()

    def _load_cache(self) -> dict[str, dict[str, Any]]:
        if not self.cache_path.exists():
            return {}
        try:
            return json.loads(self.cache_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return {}

    def _save_cache(self) -> None:
        with self._lock:
            self.cache_path.write_text(json.dumps(self._cache, indent=2, sort_keys=True), encoding="utf-8")

    def resolve(self, ip: str) -> dict[str, Any]:
        try:
            parsed = ipaddress.ip_address(ip)
        except ValueError:
            return self._unknown(ip, "Invalid address")

        if parsed.is_loopback:
            return self._local(ip, "Localhost lab", 20.0, 0.0)
        if parsed.is_private:
            return self._local(ip, "Private lab network", 10.0, 0.0)
        if parsed.is_link_local:
            return self._local(ip, "Link-local lab network", 0.0, 0.0)

        if not self.enabled:
            return {
                "ip": ip,
                "lat": 0.0,
                "lon": 0.0,
                "label": "Public IP (GeoIP disabled)",
                "country": "Unknown",
                "city": "",
                "source": "disabled",
            }

        with self._lock:
            cached = self._cache.get(ip)
        if cached:
            return cached

        result = self._lookup_public_ip(ip)
        with self._lock:
            self._cache[ip] = result
        self._save_cache()
        return result

    def _local(self, ip: str, label: str, lat: float, lon: float) -> dict[str, Any]:
        return {
            "ip": ip,
            "lat": lat,
            "lon": lon,
            "label": label,
            "country": "Lab",
            "city": "",
            "source": "local",
        }

    def _unknown(self, ip: str, reason: str) -> dict[str, Any]:
        return {
            "ip": ip,
            "lat": 0.0,
            "lon": 0.0,
            "label": reason,
            "country": "Unknown",
            "city": "",
            "source": "unknown",
        }

    def _lookup_public_ip(self, ip: str) -> dict[str, Any]:
        url = f"https://ipwho.is/{urllib.parse.quote(ip)}"
        try:
            with urllib.request.urlopen(url, timeout=2.5) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except (OSError, TimeoutError, json.JSONDecodeError) as exc:
            result = self._unknown(ip, f"GeoIP lookup failed: {exc.__class__.__name__}")
            result["source"] = "lookup_failed"
            return result

        if not payload.get("success", False):
            return self._unknown(ip, payload.get("message", "GeoIP lookup failed"))

        city = payload.get("city") or ""
        country = payload.get("country") or "Unknown"
        label = ", ".join(part for part in (city, country) if part) or country
        return {
            "ip": ip,
            "lat": float(payload.get("latitude") or 0.0),
            "lon": float(payload.get("longitude") or 0.0),
            "label": label,
            "country": country,
            "city": city,
            "source": "ipwho.is",
        }


class EventStore:
    def __init__(self, data_dir: Path, geo_resolver: GeoResolver):
        self.data_dir = data_dir
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.path = self.data_dir / "events.jsonl"
        self.siem_path = self.data_dir / "events-ecs.jsonl"
        self.geo_resolver = geo_resolver
        self._lock = threading.Lock()

    def add(self, event: dict[str, Any]) -> dict[str, Any]:
        remote_ip = str(event.get("remote_ip", ""))
        event = {
            "id": uuid4().hex[:12],
            "ts": utc_now(),
            "geo": self.geo_resolver.resolve(remote_ip),
            **event,
        }
        siem_event = self.to_siem_event(event)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
            with self.siem_path.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(siem_event, sort_keys=True) + "\n")
        return event

    def to_siem_event(self, event: dict[str, Any]) -> dict[str, Any]:
        source_ip = str(event.get("remote_ip", ""))
        destination_ip = str(event.get("local_ip", ""))
        action = str(event.get("action", "activity"))
        service = str(event.get("service", "unknown"))
        protocol = str(event.get("protocol", "tcp"))
        detail = event.get("detail") or {}
        event_categories = ["network"]
        event_types = ["connection"]
        outcome = "success"
        if action == "credential_attempt":
            event_types = ["info"]
        elif action in {"request", "post", "client_banner", "command"}:
            event_types = ["protocol"]
        elif action in {"auth_success", "auth_failed"}:
            event_categories = ["authentication"]
            event_types = ["start"]
            outcome = "success" if action == "auth_success" else "failure"

        return {
            "@timestamp": event["ts"],
            "ecs": {"version": "8.11.0"},
            "event": {
                "id": event["id"],
                "kind": "event",
                "category": event_categories,
                "type": event_types,
                "action": action,
                "dataset": f"sentineltrap.{service}",
                "outcome": outcome,
            },
            "source": {
                "ip": source_ip,
                "port": event.get("remote_port"),
                "geo": {
                    "country_name": event["geo"].get("country"),
                    "city_name": event["geo"].get("city"),
                    "location": {
                        "lat": event["geo"].get("lat"),
                        "lon": event["geo"].get("lon"),
                    },
                },
            },
            "destination": {
                "ip": destination_ip,
                "port": event.get("local_port"),
            },
            "network": {
                "transport": "tcp" if protocol in {"http", "tcp"} else protocol,
                "protocol": protocol,
                "direction": "inbound",
            },
            "service": {
                "name": service,
                "type": "honeypot",
            },
            "observer": {
                "name": "sentineltrap-sensor",
                "type": "honeypot",
                "product": "SentinelTrap Sensor",
                "vendor": "SentinelTrap",
            },
            "honeypot": {
                "id": "sentineltrap-sensor",
                "service": service,
                "emulation": True,
            },
            "related": {
                "ip": [ip for ip in (source_ip, destination_ip) if ip],
            },
            "labels": {
                "geo_source": event["geo"].get("source", "unknown"),
                "lab_safe_emulation": "true",
            },
            "message": f"{service} {action} from {source_ip}:{event.get('remote_port')}",
            "sentineltrap": {
                "detail": detail,
                "raw_event": event,
            },
        }

    def recent(self, limit: int = 250) -> list[dict[str, Any]]:
        if not self.path.exists():
            return []
        with self._lock:
            lines = self.path.read_text(encoding="utf-8").splitlines()
        events: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return events


class ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class BaseTrapHandler(socketserver.BaseRequestHandler):
    service_name = "tcp"
    banner = b""
    timeout_seconds = 8

    def setup(self) -> None:
        self.request.settimeout(self.timeout_seconds)

    @property
    def remote_ip(self) -> str:
        return str(self.client_address[0])

    @property
    def remote_port(self) -> int:
        return int(self.client_address[1])

    @property
    def local_ip(self) -> str:
        return str(self.server.server_address[0])

    @property
    def local_port(self) -> int:
        return int(self.server.server_address[1])

    def log_event(self, action: str, detail: dict[str, Any] | None = None) -> None:
        self.server.event_store.add(  # type: ignore[attr-defined]
            {
                "service": self.service_name,
                "protocol": "tcp",
                "remote_ip": self.remote_ip,
                "remote_port": self.remote_port,
                "local_ip": self.local_ip,
                "local_port": self.local_port,
                "action": action,
                "detail": detail or {},
            }
        )

    def read_line(self, limit: int = 512) -> str:
        data = bytearray()
        while len(data) < limit:
            chunk = self.request.recv(1)
            if not chunk:
                break
            if chunk in (b"\n", b"\r"):
                if data:
                    break
                continue
            data.extend(chunk)
        return data.decode("utf-8", errors="replace").strip()

    def send_line(self, text: str) -> None:
        self.request.sendall((text + "\r\n").encode("utf-8", errors="replace"))


class FakeSSHHandler(BaseTrapHandler):
    service_name = "ssh"
    banner = b"SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10\r\n"

    def handle(self) -> None:
        self.log_event("connection")
        self.request.sendall(self.banner)
        try:
            client_banner = self.request.recv(256).decode("utf-8", errors="replace").strip()
        except OSError:
            client_banner = ""
        self.log_event("client_banner", {"banner": truncate(client_banner)})


class FakeFTPHandler(BaseTrapHandler):
    service_name = "ftp"

    def handle(self) -> None:
        self.log_event("connection")
        self.send_line("220 backup-gateway FTP server ready")
        username = ""
        for _ in range(8):
            try:
                line = self.read_line()
            except OSError:
                break
            if not line:
                break
            command, _, argument = line.partition(" ")
            command = command.upper()
            self.log_event("command", {"command": command, "argument": truncate(argument)})
            if command == "USER":
                username = argument
                self.send_line("331 Password required")
            elif command == "PASS":
                self.log_event(
                    "credential_attempt",
                    {"username": truncate(username), "password": truncate(argument)},
                )
                self.send_line("530 Login incorrect")
            elif command == "QUIT":
                self.send_line("221 Goodbye")
                break
            else:
                self.send_line("502 Command not implemented")


class FakeTelnetHandler(BaseTrapHandler):
    service_name = "telnet"

    def handle(self) -> None:
        self.log_event("connection")
        try:
            self.request.sendall(b"Ubuntu 16.04 LTS\r\nlogin: ")
            username = self.read_line()
            self.request.sendall(b"Password: ")
            password = self.read_line()
            self.log_event(
                "credential_attempt",
                {"username": truncate(username), "password": truncate(password)},
            )
            self.send_line("Login incorrect")
        except OSError:
            self.log_event("disconnect")


def render_fake_http_portal() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>NexusEdge Gateway</title>
  <style>
    :root { color-scheme: light; --ink: #172033; --muted: #627086; --line: #d8e0ea;
      --panel: #ffffff; --bg: #eef3f8; --blue: #1769e0; --green: #0f9f6e; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 28px;
      font-family: Segoe UI, Arial, sans-serif; color: var(--ink);
      background: linear-gradient(135deg, #eaf1f8, #f8fbfd); }
    .shell { width: min(1060px, 100%); min-height: 620px; display: grid; grid-template-columns: 1.1fr .9fr;
      border: 1px solid var(--line); border-radius: 8px; overflow: hidden; background: var(--panel);
      box-shadow: 0 24px 70px rgba(23,32,51,.18); }
    .visual { position: relative; padding: 36px; color: white; background:
      linear-gradient(140deg, rgba(13,44,84,.96), rgba(18,89,126,.9)),
      linear-gradient(45deg, #0f2a43, #155e75); overflow: hidden; }
    .visual:before { content: ""; position: absolute; inset: 0; background:
      linear-gradient(rgba(255,255,255,.06) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,.06) 1px, transparent 1px);
      background-size: 42px 42px; opacity: .55; }
    .visual > * { position: relative; }
    .brand { display: flex; align-items: center; gap: 12px; font-weight: 800; letter-spacing: .02em; }
    .mark { width: 42px; height: 42px; border-radius: 8px; display: grid; place-items: center;
      background: rgba(255,255,255,.12); border: 1px solid rgba(255,255,255,.22); }
    .visual h1 { margin: 88px 0 12px; font-size: 38px; line-height: 1.05; }
    .visual p { max-width: 520px; margin: 0; color: #c7e5f2; line-height: 1.55; }
    .telemetry { margin-top: 38px; display: grid; gap: 12px; max-width: 480px; }
    .telemetry div { display: flex; justify-content: space-between; gap: 16px; padding: 13px 14px; border-radius: 8px;
      background: rgba(255,255,255,.1); border: 1px solid rgba(255,255,255,.16); }
    .telemetry span { color: #bfe4f4; }
    .login { display: flex; align-items: center; padding: 44px; }
    form { width: 100%; }
    h2 { margin: 0; font-size: 28px; }
    .sub { margin: 8px 0 28px; color: var(--muted); line-height: 1.5; }
    label { display: block; margin: 16px 0 7px; color: #344055; font-size: 13px; font-weight: 700; }
    input { width: 100%; height: 44px; padding: 0 12px; border: 1px solid #b8c4d2; border-radius: 8px; font-size: 15px; outline: none; }
    input:focus { border-color: var(--blue); box-shadow: 0 0 0 3px rgba(23,105,224,.12); }
    button { width: 100%; height: 44px; margin-top: 22px; border: 0; border-radius: 8px; color: white;
      background: linear-gradient(90deg, var(--blue), #0891b2); font-weight: 800; cursor: pointer; }
    .meta { display: flex; justify-content: space-between; gap: 12px; margin-top: 18px; color: var(--muted); font-size: 12px; }
    @media (max-width: 820px) {
      body { padding: 12px; }
      .shell { grid-template-columns: 1fr; min-height: 0; }
      .visual { padding: 24px; }
      .visual h1 { margin-top: 42px; font-size: 30px; }
      .login { padding: 28px; }
    }
  </style>
</head>
<body>
  <main class="shell">
    <section class="visual">
      <div class="brand">
        <div class="mark" aria-hidden="true">
          <svg viewBox="0 0 24 24" width="24" height="24" fill="none" stroke="white" stroke-width="2">
            <path d="M12 3l8 4v5c0 5-3.4 8.5-8 9-4.6-.5-8-4-8-9V7l8-4z"></path>
            <path d="M8 12h8M12 8v8"></path>
          </svg>
        </div>
        <span>NexusEdge Gateway</span>
      </div>
      <h1>Remote Access Console</h1>
      <p>Unified management for backups, routing, and secure remote administration.</p>
      <div class="telemetry" aria-hidden="true">
        <div><span>Cluster</span><strong>gateway-east-01</strong></div>
        <div><span>Firmware</span><strong>3.8.1 LTS</strong></div>
        <div><span>Access policy</span><strong>Admin only</strong></div>
      </div>
    </section>
    <section class="login">
      <form method="post" action="/login">
        <h2>Sign in</h2>
        <p class="sub">Use your administrator account to continue to the device control plane.</p>
        <label for="username">Username</label>
        <input id="username" name="username" autocomplete="username">
        <label for="password">Password</label>
        <input id="password" name="password" type="password" autocomplete="current-password">
        <button type="submit">Continue</button>
        <div class="meta"><span>TLS inspection ready</span><span>Build 3.8.1-1042</span></div>
      </form>
    </section>
  </main>
</body>
</html>"""


def make_http_honeypot_handler(store: EventStore) -> type[BaseHTTPRequestHandler]:
    class HTTPHoneypotHandler(BaseHTTPRequestHandler):
        server_version = "Apache/2.4.49"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def _headers_dict(self) -> dict[str, str]:
            return {key: value for key, value in self.headers.items()}

        def _read_body(self) -> str:
            length = min(int(self.headers.get("Content-Length", "0") or 0), MAX_BODY_BYTES)
            if length <= 0:
                return ""
            return self.rfile.read(length).decode("utf-8", errors="replace")

        def _log_request(self, action: str, extra: dict[str, Any] | None = None) -> None:
            store.add(
                {
                    "service": "http",
                    "protocol": "http",
                    "remote_ip": self.client_address[0],
                    "remote_port": self.client_address[1],
                    "local_ip": self.server.server_address[0],
                    "local_port": self.server.server_address[1],
                    "action": action,
                    "detail": {
                        "method": self.command,
                        "path": truncate(self.path),
                        "user_agent": self.headers.get("User-Agent", ""),
                        **(extra or {}),
                    },
                }
            )

        def _send_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def do_GET(self) -> None:
            self._log_request("request")
            if self.path.startswith(("/.env", "/wp-login.php", "/admin", "/phpmyadmin")):
                self._send_html("<h1>403 Forbidden</h1>", HTTPStatus.FORBIDDEN)
                return
            self._send_html(render_fake_http_portal())

        def do_POST(self) -> None:
            body = normalize_form_body(self._read_body())
            parsed = urllib.parse.parse_qs(body)
            detail = {
                "content_type": self.headers.get("Content-Type", ""),
                "body": truncate(body),
            }
            if self.path == "/login":
                username = parsed.get("username", [""])[0]
                password = parsed.get("password", [""])[0]
                detail["username"] = truncate(username)
                detail["password"] = truncate(password)
                self._log_request("credential_attempt", detail)
                self._send_html("<h1>Login failed</h1><p>Invalid username or password.</p>", HTTPStatus.UNAUTHORIZED)
                return
            self._log_request("post", detail)
            self._send_html("<h1>404 Not Found</h1>", HTTPStatus.NOT_FOUND)

    return HTTPHoneypotHandler


def make_dashboard_handler(
    store: EventStore,
    username: str,
    password: str,
) -> type[BaseHTTPRequestHandler]:
    sessions: set[str] = set()

    class DashboardHandler(BaseHTTPRequestHandler):
        server_version = "SentinelTrapDashboard/1.0"

        def log_message(self, format: str, *args: Any) -> None:
            return

        def log_dashboard_event(self, action: str, detail: dict[str, Any] | None = None) -> None:
            store.add(
                {
                    "service": "dashboard",
                    "protocol": "http",
                    "remote_ip": self.client_address[0],
                    "remote_port": self.client_address[1],
                    "local_ip": self.server.server_address[0],
                    "local_port": self.server.server_address[1],
                    "action": action,
                    "detail": detail or {},
                }
            )

        def session_token(self) -> str:
            cookie_header = self.headers.get("Cookie", "")
            cookie = SimpleCookie()
            cookie.load(cookie_header)
            morsel = cookie.get("edu_honey_session")
            return morsel.value if morsel else ""

        def is_authenticated(self) -> bool:
            token = self.session_token()
            return bool(token and token in sessions)

        def send_html(self, body: str, status: HTTPStatus = HTTPStatus.OK) -> None:
            encoded = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def send_json(self, data: Any) -> None:
            encoded = json.dumps(data).encode("utf-8")
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)

        def redirect(self, location: str) -> None:
            self.send_response(HTTPStatus.FOUND)
            self.send_header("Location", location)
            self.send_header("Cache-Control", "no-store")
            self.end_headers()

        def do_POST(self) -> None:
            if self.path != "/login":
                self.send_response(HTTPStatus.NOT_FOUND)
                self.end_headers()
                return

            length = min(int(self.headers.get("Content-Length", "0") or 0), MAX_BODY_BYTES)
            body = self.rfile.read(length).decode("utf-8", errors="replace") if length else ""
            body = normalize_form_body(body)
            form = urllib.parse.parse_qs(body)
            submitted_user = form.get("username", [""])[0]
            submitted_pass = form.get("password", [""])[0]
            valid_user = hmac.compare_digest(submitted_user, username)
            valid_pass = hmac.compare_digest(submitted_pass, password)

            if valid_user and valid_pass:
                token = secrets.token_urlsafe(32)
                sessions.add(token)
                self.log_dashboard_event("auth_success", {"username": truncate(submitted_user, 120)})
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/")
                self.send_header("Cache-Control", "no-store")
                self.send_header("Set-Cookie", f"edu_honey_session={token}; HttpOnly; SameSite=Lax; Path=/")
                self.end_headers()
                return

            self.log_dashboard_event("auth_failed", {"username": truncate(submitted_user, 120)})
            self.send_html(render_dashboard_login(error=True), HTTPStatus.UNAUTHORIZED)

        def do_GET(self) -> None:
            if self.path.startswith("/login"):
                if self.is_authenticated():
                    self.redirect("/")
                    return
                self.send_html(render_dashboard_login())
                return
            if self.path.startswith("/logout"):
                token = self.session_token()
                sessions.discard(token)
                self.send_response(HTTPStatus.FOUND)
                self.send_header("Location", "/login")
                self.send_header("Set-Cookie", "edu_honey_session=; Max-Age=0; HttpOnly; SameSite=Lax; Path=/")
                self.end_headers()
                return

            if not self.is_authenticated():
                if self.path.startswith("/api/"):
                    self.send_response(HTTPStatus.UNAUTHORIZED)
                    self.send_header("Content-Type", "application/json; charset=utf-8")
                    self.end_headers()
                    self.wfile.write(b'{"error":"authentication_required"}')
                    return
                self.redirect("/login")
                return

            if self.path.startswith("/api/events"):
                events = store.recent()
                self.send_json({"events": events})
                return
            if self.path != "/":
                self.send_response(HTTPStatus.NOT_FOUND)
                self.end_headers()
                return
            self.send_response(HTTPStatus.OK)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(load_dashboard_html().encode("utf-8"))

    return DashboardHandler


def render_dashboard_login(error: bool = False) -> str:
    error_html = "<div class=\"error\">Invalid username or password.</div>" if error else ""
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Secure Console</title>
  <style>
    :root {{ color-scheme: dark; --bg: #07111f; --panel: #0f1b2d; --line: rgba(148,163,184,.24);
      --ink: #e5edf7; --muted: #93a4ba; --blue: #38bdf8; --green: #34d399; --red: #fb7185; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; min-height: 100vh; display: grid; place-items: center; padding: 24px;
      font-family: Segoe UI, Arial, sans-serif; color: var(--ink);
      background: radial-gradient(circle at 22% 12%, rgba(56,189,248,.18), transparent 34rem),
        radial-gradient(circle at 82% 18%, rgba(52,211,153,.12), transparent 30rem), var(--bg); }}
    main {{ width: min(420px, 100%); padding: 28px; border: 1px solid var(--line); border-radius: 8px;
      background: linear-gradient(180deg, rgba(19,34,56,.96), rgba(15,27,45,.96));
      box-shadow: 0 22px 70px rgba(0,0,0,.34); }}
    .mark {{ width: 48px; height: 48px; border-radius: 8px; display: grid; place-items: center;
      background: rgba(56,189,248,.12); border: 1px solid rgba(56,189,248,.28); margin-bottom: 18px; }}
    .mark svg {{ width: 26px; height: 26px; stroke: var(--blue); }}
    h1 {{ margin: 0; font-size: 25px; }}
    p {{ margin: 8px 0 22px; color: var(--muted); line-height: 1.5; }}
    label {{ display: block; margin: 14px 0 7px; font-size: 13px; color: #cbd5e1; }}
    input {{ width: 100%; height: 44px; padding: 0 12px; color: var(--ink); background: rgba(2,6,23,.42);
      border: 1px solid rgba(148,163,184,.32); border-radius: 8px; font-size: 15px; outline: none; }}
    input:focus {{ border-color: var(--blue); box-shadow: 0 0 0 3px rgba(56,189,248,.14); }}
    button {{ width: 100%; height: 44px; margin-top: 20px; border: 0; border-radius: 8px;
      background: linear-gradient(90deg, #0284c7, #059669); color: white; font-weight: 800; cursor: pointer; }}
    .error {{ padding: 10px 12px; border: 1px solid rgba(251,113,133,.38); background: rgba(251,113,133,.12);
      color: #fecdd3; border-radius: 8px; margin-bottom: 14px; font-size: 13px; }}
    small {{ display: block; margin-top: 16px; color: var(--muted); font-size: 12px; line-height: 1.5; }}
  </style>
</head>
<body>
  <main>
    <div class="mark" aria-hidden="true">
      <svg viewBox="0 0 24 24" fill="none" stroke-width="2">
        <path d="M12 3l8 4v5c0 5-3.4 8.5-8 9-4.6-.5-8-4-8-9V7l8-4z"></path>
        <path d="M9 12l2 2 4-5"></path>
      </svg>
    </div>
    <h1>Secure Console</h1>
    <p>Authorized access only. Activity on this console is logged for lab monitoring.</p>
    {error_html}
    <form method="post" action="/login">
      <label for="username">Username</label>
      <input id="username" name="username" autocomplete="username" autofocus>
      <label for="password">Password</label>
      <input id="password" name="password" type="password" autocomplete="current-password">
      <button type="submit">Sign in</button>
    </form>
    <small>Use the dashboard credentials printed in the honeypot terminal.</small>
  </main>
</body>
</html>"""


def load_dashboard_html() -> str:
    dashboard_path = Path(__file__).with_name("dashboard.html")
    if dashboard_path.exists():
        return dashboard_path.read_text(encoding="utf-8")
    return DASHBOARD_HTML


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>SentinelTrap Sensor Dashboard</title>
  <style>
    :root { color-scheme: light; --ink: #172033; --muted: #637083; --line: #d8dee8;
      --panel: #ffffff; --bg: #f5f7fa; --accent: #0f766e; --danger: #be123c; --land: #d8e2ce; }
    * { box-sizing: border-box; }
    body { margin: 0; font-family: Arial, sans-serif; background: var(--bg); color: var(--ink); }
    header { padding: 22px 24px; background: #172033; color: white; }
    h1 { margin: 0; font-size: 24px; }
    h2 { margin: 0 0 12px; font-size: 16px; }
    header p { margin: 6px 0 0; color: #c9d3df; }
    main { max-width: 1240px; margin: 0 auto; padding: 20px 16px 32px; }
    .stats { display: grid; grid-template-columns: repeat(5, minmax(130px, 1fr)); gap: 12px; margin-bottom: 16px; }
    .stat, .panel, .table-wrap { background: var(--panel); border: 1px solid var(--line); border-radius: 8px; }
    .stat { padding: 14px; }
    .stat strong { display: block; font-size: 26px; line-height: 1.1; }
    .stat span { display: block; color: var(--muted); margin-top: 4px; font-size: 13px; }
    .overview { display: grid; grid-template-columns: minmax(360px, 1.5fr) minmax(300px, 1fr); gap: 16px; margin-bottom: 16px; }
    .panel { padding: 14px; min-width: 0; }
    .map-box { position: relative; overflow: hidden; border: 1px solid var(--line); border-radius: 8px; background: #dfeef8; }
    svg { display: block; width: 100%; height: auto; }
    .water-line { stroke: rgba(23, 32, 51, .11); stroke-width: 1; }
    .land { fill: var(--land); stroke: #b8c8ac; stroke-width: 1.2; }
    .marker { fill: var(--danger); stroke: white; stroke-width: 2; }
    .marker-ring { fill: rgba(190, 18, 60, .14); stroke: rgba(190, 18, 60, .38); stroke-width: 1; }
    .source-note { margin: 10px 0 0; color: var(--muted); font-size: 13px; }
    .table-wrap { overflow: auto; margin-top: 16px; }
    table { border-collapse: collapse; min-width: 920px; width: 100%; }
    .source-table { min-width: 560px; }
    th, td { padding: 10px 12px; border-bottom: 1px solid var(--line); text-align: left; vertical-align: top; }
    th { background: #eef2f6; font-size: 13px; color: #344055; position: sticky; top: 0; }
    td { font-size: 13px; }
    code { white-space: pre-wrap; word-break: break-word; }
    .service { display: inline-block; min-width: 54px; padding: 3px 7px; border-radius: 999px;
      background: #dbeafe; color: #1e3a8a; text-align: center; font-weight: 700; font-size: 12px; }
    .empty { padding: 28px; color: var(--muted); }
    @media (max-width: 900px) {
      .stats { grid-template-columns: repeat(2, minmax(120px, 1fr)); }
      .overview { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <header>
    <h1>SentinelTrap Sensor</h1>
    <p>Live source map and events from fake HTTP, SSH, FTP, and Telnet services.</p>
  </header>
  <main>
    <section class="stats" id="stats"></section>
    <section class="overview">
      <article class="panel">
        <h2>Source Map</h2>
        <div class="map-box">
          <svg viewBox="0 0 1000 500" role="img" aria-label="World map showing honeypot source IP locations">
            <rect x="0" y="0" width="1000" height="500" fill="#dfeef8"></rect>
            <path class="water-line" d="M0 125H1000M0 250H1000M0 375H1000M250 0V500M500 0V500M750 0V500"></path>
            <path class="land" d="M98 122c39-42 102-55 157-30 31 14 48 44 77 55 40 15 42 56 11 86-26 25-68 20-91 49-24 31-72 19-88-15-13-28-42-39-62-61-23-26-28-58-4-84z"></path>
            <path class="land" d="M214 304c31-16 76-2 94 28 19 30 9 66-15 90-29 29-25 60-50 65-25 4-39-30-48-54-12-31-28-53-26-86 1-19 17-34 45-43z"></path>
            <path class="land" d="M454 105c50-27 119-32 177-13 40 14 75 5 121 10 61 8 119 46 124 95 3 30-32 46-66 40-38-6-66 1-90 30-35 42-89 31-119 70-24 31-61 32-82 2-18-25-14-62-42-81-34-24-73-19-92-48-21-32 24-81 69-105z"></path>
            <path class="land" d="M512 269c38-21 82-8 107 22 33 39 20 97-9 134-25 32-61 46-86 25-18-15-15-48-34-74-21-29-47-40-39-72 5-18 25-27 61-35z"></path>
            <path class="land" d="M760 304c45-31 101-25 139 9 27 24 44 63 22 86-18 20-53 10-82 22-33 14-80 23-107-1-36-32-16-86 28-116z"></path>
            <g id="markers"></g>
          </svg>
        </div>
        <p class="source-note" id="mapNote">Waiting for scan traffic...</p>
      </article>
      <article class="panel">
        <h2>Top Sources</h2>
        <div class="table-wrap" style="margin-top:0">
          <table class="source-table">
            <thead>
              <tr><th>Source</th><th>Hits</th><th>Services</th><th>Location</th></tr>
            </thead>
            <tbody id="sources"><tr><td colspan="4" class="empty">Waiting for sources...</td></tr></tbody>
          </table>
        </div>
      </article>
    </section>
    <section class="table-wrap">
      <table>
        <thead>
          <tr><th>Time</th><th>Service</th><th>Source</th><th>Action</th><th>Detail</th></tr>
        </thead>
        <tbody id="events"><tr><td colspan="5" class="empty">Waiting for events...</td></tr></tbody>
      </table>
    </section>
  </main>
  <script>
    const statsEl = document.getElementById('stats');
    const eventsEl = document.getElementById('events');
    const sourcesEl = document.getElementById('sources');
    const markersEl = document.getElementById('markers');
    const mapNoteEl = document.getElementById('mapNote');

    function escapeHtml(value) {
      return String(value ?? '').replace(/[&<>"']/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      }[ch]));
    }

    function aggregateSources(events) {
      const sources = new Map();
      for (const event of events) {
        const ip = event.remote_ip || 'unknown';
        if (!sources.has(ip)) {
          sources.set(ip, { ip, hits: 0, services: new Set(), actions: new Set(), geo: event.geo || {}, last: event });
        }
        const source = sources.get(ip);
        source.hits += 1;
        source.services.add(event.service || 'unknown');
        source.actions.add(event.action || 'unknown');
        source.geo = event.geo || source.geo;
        source.last = event;
      }
      return Array.from(sources.values()).sort((a, b) => b.hits - a.hits);
    }

    function project(lat, lon) {
      const x = ((Number(lon) + 180) / 360) * 1000;
      const y = ((90 - Number(lat)) / 180) * 500;
      return { x: Math.max(8, Math.min(992, x)), y: Math.max(8, Math.min(492, y)) };
    }

    function locationLabel(geo) {
      if (!geo) return 'Unknown';
      if (geo.label) return geo.label;
      return [geo.city, geo.country].filter(Boolean).join(', ') || 'Unknown';
    }

    function renderStats(events, sources) {
      const services = {};
      for (const event of events) services[event.service] = (services[event.service] || 0) + 1;
      const credentialAttempts = events.filter(e => e.action === 'credential_attempt').length;
      const scanHits = events.filter(e => ['connection', 'request', 'post'].includes(e.action)).length;
      const cards = [
        ['Events', events.length],
        ['Sources', sources.length],
        ['Scan hits', scanHits],
        ['HTTP hits', services.http || 0],
        ['SSH hits', services.ssh || 0],
      ];
      statsEl.innerHTML = cards.map(([label, value]) =>
        `<article class="stat"><strong>${value}</strong><span>${label}</span></article>`
      ).join('');
    }

    function renderMap(sources) {
      markersEl.innerHTML = '';
      if (!sources.length) {
        mapNoteEl.textContent = 'Waiting for scan traffic...';
        return;
      }
      for (const source of sources) {
        const geo = source.geo || {};
        const point = project(geo.lat || 0, geo.lon || 0);
        const radius = Math.min(30, 8 + source.hits * 2);
        const title = `${source.ip} - ${source.hits} hit(s) - ${locationLabel(geo)}`;
        markersEl.insertAdjacentHTML('beforeend', `
          <circle class="marker-ring" cx="${point.x}" cy="${point.y}" r="${radius}">
            <title>${escapeHtml(title)}</title>
          </circle>
          <circle class="marker" cx="${point.x}" cy="${point.y}" r="5">
            <title>${escapeHtml(title)}</title>
          </circle>
        `);
      }
      const geoSources = sources.filter(s => s.geo && s.geo.source === 'ipwho.is').length;
      const labSources = sources.filter(s => s.geo && ['local', 'disabled'].includes(s.geo.source)).length;
      mapNoteEl.textContent = `${sources.length} source(s): ${geoSources} public GeoIP location(s), ${labSources} lab or non-enriched source(s).`;
    }

    function renderSources(sources) {
      if (!sources.length) {
        sourcesEl.innerHTML = '<tr><td colspan="4" class="empty">Waiting for sources...</td></tr>';
        return;
      }
      sourcesEl.innerHTML = sources.slice(0, 10).map(source => {
        const services = Array.from(source.services).sort().join(', ');
        return `<tr>
          <td>${escapeHtml(source.ip)}</td>
          <td>${source.hits}</td>
          <td>${escapeHtml(services)}</td>
          <td>${escapeHtml(locationLabel(source.geo))}</td>
        </tr>`;
      }).join('');
    }

    function renderEvents(events) {
      if (!events.length) {
        eventsEl.innerHTML = '<tr><td colspan="5" class="empty">Waiting for events...</td></tr>';
        return;
      }
      eventsEl.innerHTML = events.slice().reverse().map(event => {
        const detail = JSON.stringify(event.detail || {}, null, 2);
        return `<tr>
          <td>${escapeHtml(event.ts)}</td>
          <td><span class="service">${escapeHtml(event.service)}</span></td>
          <td>${escapeHtml(event.remote_ip)}:${escapeHtml(event.remote_port)}<br>${escapeHtml(locationLabel(event.geo))}</td>
          <td>${escapeHtml(event.action)}</td>
          <td><code>${escapeHtml(detail)}</code></td>
        </tr>`;
      }).join('');
    }

    async function refresh() {
      const response = await fetch('/api/events', { cache: 'no-store' });
      const data = await response.json();
      const events = data.events || [];
      const sources = aggregateSources(events);
      renderStats(events, sources);
      renderMap(sources);
      renderSources(sources);
      renderEvents(events);
    }

    refresh();
    setInterval(refresh, 2000);
  </script>
</body>
</html>"""


def add_event_store_to_server(server: Any, store: EventStore) -> None:
    server.event_store = store


def start_http_server(
    label: str,
    bind: str,
    port: int,
    handler: type[BaseHTTPRequestHandler],
) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((bind, port), handler)
    thread = threading.Thread(target=server.serve_forever, name=label, daemon=True)
    thread.start()
    return server


def start_tcp_server(
    label: str,
    bind: str,
    port: int,
    handler: type[BaseTrapHandler],
    store: EventStore,
) -> ThreadedTCPServer:
    server = ThreadedTCPServer((bind, port), handler)
    add_event_store_to_server(server, store)
    thread = threading.Thread(target=server.serve_forever, name=label, daemon=True)
    thread.start()
    return server


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a small network deception sensor.")
    parser.add_argument("--bind", default="127.0.0.1", help="Address to bind services to. Default: 127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8080, help="Fake HTTP login port.")
    parser.add_argument("--ssh-port", type=int, default=2222, help="Fake SSH port.")
    parser.add_argument("--ftp-port", type=int, default=2121, help="Fake FTP port.")
    parser.add_argument("--telnet-port", type=int, default=2323, help="Fake Telnet port.")
    parser.add_argument("--dashboard-port", type=int, default=5000, help="Dashboard port.")
    parser.add_argument(
        "--dashboard-user",
        default=os.environ.get("SENTINELTRAP_DASHBOARD_USER", "operator"),
    )
    parser.add_argument(
        "--dashboard-password",
        default=os.environ.get("SENTINELTRAP_DASHBOARD_PASSWORD"),
        help="Dashboard password. If omitted, a random password is generated and printed at startup.",
    )
    parser.add_argument("--data-dir", default="data", help="Directory for events.jsonl.")
    parser.add_argument(
        "--geo-lookup",
        action="store_true",
        help="Look up public source IP locations with ipwho.is and cache them in the data directory.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    data_dir = Path(args.data_dir)
    dashboard_password = args.dashboard_password or secrets.token_urlsafe(12)
    generated_dashboard_password = args.dashboard_password is None
    geo_resolver = GeoResolver(data_dir, enabled=args.geo_lookup)
    store = EventStore(data_dir, geo_resolver)
    servers: list[Any] = []
    stop = threading.Event()

    def request_stop(signum: int, frame: Any) -> None:
        stop.set()

    signal.signal(signal.SIGINT, request_stop)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, request_stop)

    if args.bind not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: Binding outside localhost can expose this honeypot to other machines.")
        print("Use a lab network, firewall rules, and permission from the network owner.")

    services = [
        ("http", args.http_port, "Fake HTTP login", lambda: start_http_server(
            "http-honeypot", args.bind, args.http_port, make_http_honeypot_handler(store)
        )),
        ("ssh", args.ssh_port, "Fake SSH banner", lambda: start_tcp_server(
            "ssh-honeypot", args.bind, args.ssh_port, FakeSSHHandler, store
        )),
        ("ftp", args.ftp_port, "Fake FTP prompt", lambda: start_tcp_server(
            "ftp-honeypot", args.bind, args.ftp_port, FakeFTPHandler, store
        )),
        ("telnet", args.telnet_port, "Fake Telnet prompt", lambda: start_tcp_server(
            "telnet-honeypot", args.bind, args.telnet_port, FakeTelnetHandler, store
        )),
        ("dashboard", args.dashboard_port, "Dashboard", lambda: start_http_server(
            "dashboard",
            args.bind,
            args.dashboard_port,
            make_dashboard_handler(store, args.dashboard_user, dashboard_password),
        )),
    ]

    for name, port, description, starter in services:
        try:
            servers.append(starter())
            print(f"{description:18} listening on {args.bind}:{port}")
        except OSError as exc:
            print(f"Could not start {name} on {args.bind}:{port}: {exc}")

    print(f"Events log: {Path(args.data_dir).resolve() / 'events.jsonl'}")
    print(f"SIEM/ECS log: {Path(args.data_dir).resolve() / 'events-ecs.jsonl'}")
    if args.geo_lookup:
        print(f"GeoIP lookup: enabled, cache at {data_dir.resolve() / 'geo-cache.json'}")
    else:
        print("GeoIP lookup: disabled for public IPs. Use --geo-lookup to enable it.")
    print(f"Dashboard:  http://{args.bind}:{args.dashboard_port}/")
    print(f"Dashboard user: {args.dashboard_user}")
    if generated_dashboard_password:
        print(f"Dashboard password: {dashboard_password}")
    else:
        print("Dashboard password: set from argument or environment")
    print("Isolation note: this honeypot emulates services and does not execute submitted payloads.")
    print("For exposed labs, run it inside a VM/container and firewall it away from production systems.")
    print("Press Ctrl+C to stop.")

    try:
        while not stop.is_set():
            time.sleep(0.3)
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()
        print("Stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
