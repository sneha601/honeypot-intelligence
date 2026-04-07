"""
FTP Honeypot Trap
-----------------
Emulates a ProFTPD server. Captures:
  - All login attempts (USER + PASS commands)
  - File operations (RETR, STOR, LIST, etc.)
"""

import asyncio
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import reporter
import config

_COMMANDS = {
    "SYST": "215 UNIX Type: L8\r\n",
    "FEAT": "211-Features:\r\n PASV\r\n UTF8\r\n211 End\r\n",
    "PWD":  '257 "/" is the current directory\r\n',
    "TYPE": "200 Type set to I\r\n",
    "PASV": "227 Entering Passive Mode (127,0,0,1,196,244)\r\n",
    "LIST": "150 Here comes the directory listing.\r\n226 Directory send OK.\r\n",
    "NLST": "150 Here comes the directory listing.\r\n226 Directory send OK.\r\n",
    "NOOP": "200 NOOP ok.\r\n",
    "QUIT": "221 Goodbye.\r\n",
}


async def _handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
    peer = writer.get_extra_info("peername")
    ip, port = (peer[0], peer[1]) if peer else ("0.0.0.0", 0)

    await reporter.report(ip, port, "ftp", "connection", {"event": "new_connection"})

    writer.write(f"{config.FTP_BANNER}\r\n".encode())
    await writer.drain()

    username = None

    try:
        while True:
            try:
                line = await asyncio.wait_for(reader.readline(), timeout=30)
            except asyncio.TimeoutError:
                break
            if not line:
                break

            cmd_line = line.decode(errors="replace").strip()
            if not cmd_line:
                continue

            parts = cmd_line.split(" ", 1)
            cmd = parts[0].upper()
            arg = parts[1] if len(parts) > 1 else ""

            print(f"[FTP] {ip} → {cmd} {arg}")

            if cmd == "USER":
                username = arg
                writer.write(f"331 Password required for {username}\r\n".encode())

            elif cmd == "PASS":
                await reporter.report(
                    ip, port, "ftp", "credential_attempt",
                    {"username": username or "", "password": arg},
                )
                # Always deny but look realistic
                writer.write(b"530 Login incorrect.\r\n")

            elif cmd in ("RETR", "STOR", "DELE", "MKD", "RMD", "RNFR", "RNTO"):
                await reporter.report(
                    ip, port, "ftp", "file_operation",
                    {"command": cmd, "argument": arg},
                )
                writer.write(b"550 Permission denied.\r\n")

            elif cmd in _COMMANDS:
                writer.write(_COMMANDS[cmd].encode())

            else:
                writer.write(b"500 Unknown command.\r\n")

            await writer.drain()

            if cmd == "QUIT":
                break

    except Exception:
        pass
    finally:
        writer.close()


async def start():
    server = await asyncio.start_server(_handle, "0.0.0.0", config.FTP_PORT)
    print(f"[FTP] Honeypot listening on port {config.FTP_PORT}")
    async with server:
        await server.serve_forever()
