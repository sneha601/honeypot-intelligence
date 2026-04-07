import httpx
import asyncio
import json
from datetime import datetime
from typing import Any, Dict, Optional
import config

# Queue events locally if central server is unreachable
_queue: asyncio.Queue = asyncio.Queue(maxsize=10000)
_started = False


async def report(
    attacker_ip: str,
    attacker_port: int,
    service: str,
    event_type: str,
    data: Dict[str, Any] = None,
    raw_payload: Optional[str] = None,
):
    """Queue an event for sending to the central server."""
    event = {
        "node_id": config.NODE_ID,
        "timestamp": datetime.utcnow().isoformat(),
        "attacker_ip": attacker_ip,
        "attacker_port": attacker_port,
        "service": service,
        "event_type": event_type,
        "data": data or {},
        "raw_payload": raw_payload,
    }
    try:
        _queue.put_nowait(event)
    except asyncio.QueueFull:
        print(f"[!] Reporter queue full — dropping event from {attacker_ip}")


async def start_sender():
    """Background task: drain the queue and POST events to central server."""
    global _started
    if _started:
        return
    _started = True

    async with httpx.AsyncClient(timeout=10.0) as client:
        while True:
            event = await _queue.get()
            try:
                resp = await client.post(
                    f"{config.CENTRAL_SERVER}/api/events",
                    json=event,
                )
                if resp.status_code not in (200, 201):
                    print(f"[!] Central server returned {resp.status_code}: {resp.text[:100]}")
            except httpx.RequestError as e:
                print(f"[!] Could not reach central server: {e} — will retry")
                # Put back at front (best-effort)
                await asyncio.sleep(5)
                try:
                    _queue.put_nowait(event)
                except asyncio.QueueFull:
                    pass
            finally:
                _queue.task_done()
