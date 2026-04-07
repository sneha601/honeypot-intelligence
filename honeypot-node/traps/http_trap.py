"""
HTTP Honeypot Trap
------------------
Mimics a vulnerable web server:
  - WordPress admin login (/wp-admin, /wp-login.php)
  - phpMyAdmin (/phpmyadmin)
  - Generic admin panel (/admin)
  - .env / config file exposure
  - Generic catch-all that records every request

All form submissions are logged (credentials, payloads).
"""

import asyncio
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import reporter
import config

# ── Fake pages ────────────────────────────────────────────────────────────────

_WP_LOGIN = b"""HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.4.41 (Ubuntu)\r\nX-Powered-By: PHP/7.4.3\r\n\r\n
<!DOCTYPE html><html><head><title>Log In &lsaquo; Demo Site &#8212; WordPress</title></head>
<body class="login">
<div id="login"><h1>WordPress</h1>
<form name="loginform" action="/wp-login.php" method="post">
<p><label>Username<br><input type="text" name="log" size="20"/></label></p>
<p><label>Password<br><input type="password" name="pwd" size="20"/></label></p>
<p><input type="submit" value="Log In"/></p>
</form></div></body></html>"""

_PHPMYADMIN = b"""HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: Apache/2.4.41\r\n\r\n
<!DOCTYPE html><html><head><title>phpMyAdmin</title></head>
<body><div id="login_form">
<form method="post" action="/phpmyadmin/index.php">
<input type="text" name="pma_username" placeholder="Username"/>
<input type="password" name="pma_password" placeholder="Password"/>
<input type="submit" value="Go"/>
</form></div></body></html>"""

_ADMIN = b"""HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nServer: nginx/1.18.0\r\n\r\n
<!DOCTYPE html><html><head><title>Admin Panel</title></head>
<body><h2>Administration Login</h2>
<form method="post" action="/admin/login">
<input type="text" name="username" placeholder="Username"/>
<input type="password" name="password" placeholder="Password"/>
<input type="submit" value="Login"/>
</form></body></html>"""

_ENV_FILE = b"""HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nServer: Apache/2.4.41\r\n\r\n
APP_ENV=production
APP_KEY=base64:FAKE_KEY_FOR_HONEYPOT_ONLY
DB_HOST=127.0.0.1
DB_DATABASE=production_db
DB_USERNAME=dbadmin
DB_PASSWORD=SuperSecret123!
MAIL_PASSWORD=smtp_password_here
AWS_SECRET=AKIAIOSFODNN7EXAMPLE"""

_404 = b"HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\nServer: Apache/2.4.41\r\n\r\n<h1>404 Not Found</h1>"
_200 = b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html><body><h1>It works!</h1></body></html>"


# ── Request parser ─────────────────────────────────────────────────────────────

def _parse_request(raw: bytes):
    try:
        header_section, _, body = raw.partition(b"\r\n\r\n")
        lines = header_section.decode(errors="replace").split("\r\n")
        method, path, *_ = lines[0].split(" ")
        headers = {}
        for line in lines[1:]:
            if ": " in line:
                k, v = line.split(": ", 1)
                headers[k.lower()] = v
        return method, path, headers, body.decode(errors="replace")
    except Exception:
        return "GET", "/", {}, ""


def _parse_form(body: str) -> dict:
    """Parse application/x-www-form-urlencoded body."""
    from urllib.parse import parse_qs, unquote_plus
    result = {}
    for k, v in parse_qs(body).items():
        result[unquote_plus(k)] = unquote_plus(v[0]) if v else ""
    return result


# ── Handler ───────────────────────────────────────────────────────────────────

async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip, port = (peer[0], peer[1]) if peer else ("0.0.0.0", 0)

    try:
        raw = await asyncio.wait_for(reader.read(8192), timeout=10)
    except asyncio.TimeoutError:
        writer.close()
        return

    method, path, headers, body = _parse_request(raw)
    ua = headers.get("user-agent", "")
    path_lower = path.lower().split("?")[0]

    # Determine event type and log
    event_data = {
        "method": method,
        "path": path,
        "user_agent": ua,
        "host": headers.get("host", ""),
        "content_type": headers.get("content-type", ""),
    }

    # POST — capture credentials/payloads
    if method == "POST" and body:
        form = _parse_form(body)
        event_data["post_data"] = form
        event_type = "credential_attempt"
    else:
        event_type = "scan_probe"

    await reporter.report(ip, port, "http", event_type, event_data,
                          raw_payload=body if body else None)
    print(f"[HTTP] {ip} {method} {path} ({ua[:60]})")

    # Choose response
    if path_lower in ("/wp-login.php", "/wp-admin", "/wp-admin/"):
        response = _WP_LOGIN
    elif "phpmyadmin" in path_lower:
        response = _PHPMYADMIN
    elif path_lower in ("/admin", "/admin/", "/admin/login", "/administrator"):
        response = _ADMIN
    elif path_lower in ("/.env", "/config.php", "/config.env", "/.env.local", "/env"):
        response = _ENV_FILE
    elif path_lower in ("/", "/index.html", "/index.php"):
        response = _200
    else:
        response = _404

    writer.write(response)
    await writer.drain()
    writer.close()


async def start():
    server = await asyncio.start_server(_handle, "0.0.0.0", config.HTTP_PORT)
    print(f"[HTTP] Honeypot listening on port {config.HTTP_PORT}")
    async with server:
        await server.serve_forever()
