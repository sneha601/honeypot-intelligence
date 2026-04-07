"""
Honeypot Node — Entry Point
---------------------------
Starts all traps concurrently and the event reporter background task.
"""

import asyncio
import sys
import os

import config
import reporter
from traps import ssh_trap, http_trap, ftp_trap, telnet_trap


async def main():
    print(f"[*] Starting Honeypot Node: {config.NODE_ID}")
    print(f"[*] Central server: {config.CENTRAL_SERVER}")

    loop = asyncio.get_event_loop()

    await asyncio.gather(
        reporter.start_sender(),
        ssh_trap.start(loop),
        http_trap.start(),
        ftp_trap.start(),
        telnet_trap.start(),
    )


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Honeypot node stopped.")
