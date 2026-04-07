import asyncio
import json
import os
from typing import List

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, FileResponse
from fastapi.staticfiles import StaticFiles

import database
import analyzer
import ioc_generator
from models import AttackEvent

app = FastAPI(title="Honeypot Intelligence Network", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# WebSocket clients connected to live dashboard
_ws_clients: List[WebSocket] = []


# ─── Startup ─────────────────────────────────────────────────────────────────

@app.on_event("startup")
async def startup():
    await database.init_db()
    print("[*] Database initialised")


# ─── Event Ingestion ──────────────────────────────────────────────────────────

@app.post("/api/events", status_code=201)
async def receive_event(event: AttackEvent):
    """Honeypot nodes POST attack events here."""
    # Persist
    event_id = await database.store_event(event)

    # Geo-enrichment (non-blocking)
    geo = await analyzer.geolocate(event.attacker_ip)
    await database.update_event_geo(event_id, geo)

    # Threat analysis
    threat = await analyzer.analyze_event(event)

    # IOC promotion
    iocs = await ioc_generator.check_and_generate(event.attacker_ip)
    if event.raw_payload:
        ioc = await ioc_generator.generate_payload_ioc(event.raw_payload, event.attacker_ip)
        iocs.append(ioc)

    # Broadcast to live dashboard
    await _broadcast({
        "type": "event",
        "data": {
            "event": {**event.dict(), "id": event_id},
            "geo": geo,
            "threat": threat,
            "iocs": iocs,
        }
    })

    return {"status": "ok", "event_id": event_id, "threat": threat}


# ─── Query Endpoints ──────────────────────────────────────────────────────────

@app.get("/api/stats")
async def get_stats():
    return await database.get_stats()


@app.get("/api/events")
async def get_events(limit: int = Query(100, ge=1, le=1000)):
    return await database.get_recent_events(limit)


@app.get("/api/top-attackers")
async def top_attackers(limit: int = Query(20, ge=1, le=100)):
    return await database.get_top_attackers(limit)


@app.get("/api/iocs")
async def get_iocs(limit: int = Query(200, ge=1, le=10000)):
    return await database.get_iocs(limit)


@app.get("/api/map")
async def get_map_data():
    return await database.get_geo_map_data()


# ─── Export Endpoints ─────────────────────────────────────────────────────────

@app.get("/api/export/blocklist", response_class=PlainTextResponse)
async def export_blocklist():
    content = await ioc_generator.export_blocklist()
    return PlainTextResponse(content, media_type="text/plain")


@app.get("/api/export/yara", response_class=PlainTextResponse)
async def export_yara():
    content = await ioc_generator.export_yara_rule()
    return PlainTextResponse(content, media_type="text/plain")


# ─── WebSocket (live dashboard) ───────────────────────────────────────────────

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    _ws_clients.append(websocket)
    try:
        # Send current stats on connect
        stats = await database.get_stats()
        recent = await database.get_recent_events(20)
        map_data = await database.get_geo_map_data(200)
        top = await database.get_top_attackers(10)
        await websocket.send_json({
            "type": "init",
            "data": {"stats": stats, "recent_events": recent,
                     "map_data": map_data, "top_attackers": top}
        })
        while True:
            # Keep connection alive; client may send pings
            await asyncio.wait_for(websocket.receive_text(), timeout=30)
    except (WebSocketDisconnect, asyncio.TimeoutError, Exception):
        pass
    finally:
        if websocket in _ws_clients:
            _ws_clients.remove(websocket)


async def _broadcast(payload: dict):
    dead = []
    for ws in _ws_clients:
        try:
            await ws.send_json(payload)
        except Exception:
            dead.append(ws)
    for ws in dead:
        if ws in _ws_clients:
            _ws_clients.remove(ws)


# ─── Dashboard static files ───────────────────────────────────────────────────

DASHBOARD_PATH = os.path.join(os.path.dirname(__file__), "..", "dashboard")
if os.path.isdir(DASHBOARD_PATH):
    app.mount("/", StaticFiles(directory=DASHBOARD_PATH, html=True), name="dashboard")


# ─── Run directly ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
