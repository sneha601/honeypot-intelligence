"""
SSH Honeypot Trap
-----------------
Uses paramiko to present a real SSH handshake.
Logs every credential attempt but always denies access.
Optionally accepts connections to a fake shell to capture commands.
"""

import asyncio
import socket
import threading
import paramiko
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import reporter
import config

# Generate or load a persistent host key
HOST_KEY_PATH = "ssh_host_rsa.key"


def _get_host_key() -> paramiko.RSAKey:
    if os.path.exists(HOST_KEY_PATH):
        return paramiko.RSAKey(filename=HOST_KEY_PATH)
    key = paramiko.RSAKey.generate(2048)
    key.write_private_key_file(HOST_KEY_PATH)
    return key


HOST_KEY = _get_host_key()


class _FakeSSHServer(paramiko.ServerInterface):
    def __init__(self, client_ip: str, client_port: int, loop: asyncio.AbstractEventLoop):
        self.client_ip = client_ip
        self.client_port = client_port
        self.loop = loop
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == "session":
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username: str, password: str):
        asyncio.run_coroutine_threadsafe(
            reporter.report(
                attacker_ip=self.client_ip,
                attacker_port=self.client_port,
                service="ssh",
                event_type="credential_attempt",
                data={"username": username, "password": password},
            ),
            self.loop,
        )
        print(f"[SSH] {self.client_ip} tried {username}:{password}")
        return paramiko.AUTH_FAILED  # Always deny

    def check_auth_publickey(self, username, key):
        asyncio.run_coroutine_threadsafe(
            reporter.report(
                attacker_ip=self.client_ip,
                attacker_port=self.client_port,
                service="ssh",
                event_type="credential_attempt",
                data={"username": username, "auth_type": "publickey",
                      "key_fingerprint": key.get_fingerprint().hex()},
            ),
            self.loop,
        )
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password,publickey"

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command: bytes):
        cmd = command.decode(errors="replace")
        asyncio.run_coroutine_threadsafe(
            reporter.report(
                attacker_ip=self.client_ip,
                attacker_port=self.client_port,
                service="ssh",
                event_type="command_executed",
                data={"command": cmd},
                raw_payload=cmd,
            ),
            self.loop,
        )
        return True


def _handle_client(conn: socket.socket, addr, loop: asyncio.AbstractEventLoop):
    ip, port = addr[0], addr[1]
    transport = None
    try:
        transport = paramiko.Transport(conn)
        transport.local_version = config.SSH_BANNER
        transport.add_server_key(HOST_KEY)

        server = _FakeSSHServer(ip, port, loop)
        transport.start_server(server=server)

        # Wait for auth attempts (up to 60 s)
        chan = transport.accept(60)
        if chan is not None:
            # Fake shell: capture any commands the attacker types
            chan.send("\r\nWelcome to Ubuntu 22.04.3 LTS (GNU/Linux 5.15.0-91-generic x86_64)\r\n\r\n$ ")
            buf = b""
            while True:
                data = chan.recv(1024)
                if not data:
                    break
                buf += data
                chan.send(data)  # echo
                if b"\r" in buf or b"\n" in buf:
                    cmd = buf.decode(errors="replace").strip()
                    if cmd:
                        asyncio.run_coroutine_threadsafe(
                            reporter.report(
                                attacker_ip=ip,
                                attacker_port=port,
                                service="ssh",
                                event_type="command_executed",
                                data={"command": cmd},
                                raw_payload=cmd,
                            ),
                            loop,
                        )
                        chan.send(f"\r\nbash: {cmd.split()[0]}: command not found\r\n$ ")
                    buf = b""
    except Exception:
        pass
    finally:
        if transport:
            transport.close()
        conn.close()


async def start(loop: asyncio.AbstractEventLoop = None):
    if loop is None:
        loop = asyncio.get_event_loop()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("0.0.0.0", config.SSH_PORT))
    sock.listen(100)
    sock.setblocking(False)
    print(f"[SSH] Honeypot listening on port {config.SSH_PORT}")

    while True:
        conn, addr = await loop.sock_accept(sock)
        ip, port = addr
        asyncio.run_coroutine_threadsafe(
            reporter.report(ip, port, "ssh", "connection", {"event": "new_connection"}),
            loop,
        )
        # Handle in a thread (paramiko is blocking)
        t = threading.Thread(target=_handle_client, args=(conn, addr, loop), daemon=True)
        t.start()
