"""
Telnet Honeypot Trap
--------------------
Mirai botnet and all its variants exclusively target Telnet (port 23).
This trap presents a realistic router/IoT login prompt and captures:
  - Every credential pair attempted
  - Every command typed if the attacker stays connected
  - Raw payload if a script is pasted in
"""

import asyncio
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import reporter
import config

# Mimic common IoT/router banners to attract bots
_BANNERS = [
    b"\r\nBusyBox v1.19.4 built-in shell (ash)\r\nEnter 'help' for a list of built-in commands\r\n\r\n",
    b"\r\nTP-LINK Wireless Router\r\nModel: TL-WR841N\r\n\r\n",
    b"\r\nHuawei Home Gateway\r\n\r\n",
    b"\r\nDVR Login\r\n\r\n",
]
import random


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip, port = (peer[0], peer[1]) if peer else ("0.0.0.0", 0)

    await reporter.report(ip, port, "telnet", "connection", {"event": "new_connection"})

    # Pick a random banner to appear as different device types
    banner = random.choice(_BANNERS)
    writer.write(banner)
    writer.write(b"login: ")
    await writer.drain()

    username = ""
    password = ""
    commands_buf = []

    try:
        # ── Capture username ──────────────────────────────────────────────────
        username = await _read_line(reader, writer, echo=True, timeout=15)
        if not username:
            writer.close()
            return

        writer.write(b"Password: ")
        await writer.drain()

        # ── Capture password (no echo) ────────────────────────────────────────
        password = await _read_line(reader, writer, echo=False, timeout=15)

        await reporter.report(
            ip, port, "telnet", "credential_attempt",
            {"username": username, "password": password},
        )
        print(f"[Telnet] {ip} tried {username}:{password}")

        # Simulate a brief pause then "wrong password" — realistic
        await asyncio.sleep(1.5)
        writer.write(b"\r\nLogin incorrect\r\n\r\nlogin: ")
        await writer.drain()

        # Second attempt — some bots try multiple credential pairs
        username2 = await _read_line(reader, writer, echo=True, timeout=10)
        if username2:
            writer.write(b"Password: ")
            await writer.drain()
            password2 = await _read_line(reader, writer, echo=False, timeout=10)
            if password2:
                await reporter.report(
                    ip, port, "telnet", "credential_attempt",
                    {"username": username2, "password": password2, "attempt": 2},
                )

        # Third attempt — let attacker "in" to capture shell commands
        username3 = await _read_line(reader, writer, echo=True, timeout=10)
        if username3:
            writer.write(b"Password: ")
            await writer.drain()
            password3 = await _read_line(reader, writer, echo=False, timeout=10)
            if password3:
                await reporter.report(
                    ip, port, "telnet", "credential_attempt",
                    {"username": username3, "password": password3, "attempt": 3},
                )
                # Give a fake shell — capture commands
                writer.write(b"\r\n# ")
                await writer.drain()
                await _fake_shell(reader, writer, ip, port)

    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass
    except Exception:
        pass
    finally:
        writer.close()


async def _fake_shell(reader, writer, ip, port):
    """Present a minimal BusyBox-like shell and capture everything typed."""
    buf = b""
    raw_session = b""

    try:
        for _ in range(30):  # Max 30 commands before disconnecting
            data = await asyncio.wait_for(reader.read(512), timeout=20)
            if not data:
                break
            raw_session += data
            buf += data

            # Commands end with \r or \n
            while b"\r" in buf or b"\n" in buf:
                sep = b"\r" if b"\r" in buf else b"\n"
                line, _, buf = buf.partition(sep)
                cmd = line.decode(errors="replace").strip()
                if not cmd:
                    continue

                await reporter.report(
                    ip, port, "telnet", "command_executed",
                    {"command": cmd},
                    raw_payload=cmd,
                )
                print(f"[Telnet] {ip} shell$ {cmd}")

                # Fake responses to keep bot engaged
                if cmd in ("id", "whoami"):
                    writer.write(b"uid=0(root) gid=0(root) groups=0(root)\r\n")
                elif cmd.startswith("uname"):
                    writer.write(b"Linux router 2.6.36 #1 SMP PREEMPT armv7l\r\n")
                elif cmd.startswith("cat /proc/cpuinfo"):
                    writer.write(b"Processor: ARMv7\r\nBogoMIPS: 532.48\r\n")
                elif cmd in ("ls", "ls /"):
                    writer.write(b"bin  dev  etc  lib  mnt  proc  sys  tmp  usr  var\r\n")
                elif cmd.startswith("wget") or cmd.startswith("curl"):
                    # This is the money shot — malware download attempt
                    writer.write(b"")
                elif cmd in ("exit", "logout"):
                    writer.write(b"logout\r\n")
                    return
                else:
                    writer.write(f"{cmd.split()[0]}: not found\r\n".encode())

                writer.write(b"# ")
                await writer.drain()

        # Report the full session raw payload if substantial
        if len(raw_session) > 10:
            await reporter.report(
                ip, port, "telnet", "payload_dropped",
                {"session_length": len(raw_session)},
                raw_payload=raw_session.decode(errors="replace"),
            )
    except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
        pass


async def _read_line(reader, writer, echo: bool, timeout: int) -> str:
    """Read a line char-by-char to handle raw telnet clients."""
    buf = b""
    try:
        while True:
            ch = await asyncio.wait_for(reader.read(1), timeout=timeout)
            if not ch or ch in (b"\r", b"\n"):
                break
            # Skip telnet IAC negotiation bytes
            if ch == b"\xff":
                await reader.read(2)
                continue
            buf += ch
            if echo:
                writer.write(ch)
                await writer.drain()
    except asyncio.TimeoutError:
        pass
    return buf.decode(errors="replace").strip()


async def start():
    server = await asyncio.start_server(_handle, "0.0.0.0", config.TELNET_PORT)
    print(f"[Telnet] Honeypot listening on port {config.TELNET_PORT}")
    async with server:
        await server.serve_forever()
