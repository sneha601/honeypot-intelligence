import aiosqlite
import json
from datetime import datetime
from typing import List, Dict, Any, Optional

DB_PATH = "honeypot.db"


async def init_db():
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id     TEXT NOT NULL,
                timestamp   TEXT NOT NULL,
                attacker_ip TEXT NOT NULL,
                attacker_port INTEGER,
                service     TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                data        TEXT DEFAULT '{}',
                raw_payload TEXT,
                country     TEXT DEFAULT 'Unknown',
                country_code TEXT DEFAULT 'XX',
                city        TEXT DEFAULT 'Unknown',
                lat         REAL DEFAULT 0.0,
                lon         REAL DEFAULT 0.0,
                isp         TEXT DEFAULT 'Unknown'
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS iocs (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type    TEXT NOT NULL,
                value       TEXT NOT NULL UNIQUE,
                confidence  REAL DEFAULT 0.5,
                tags        TEXT DEFAULT '[]',
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                hit_count   INTEGER DEFAULT 1
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS nodes (
                node_id     TEXT PRIMARY KEY,
                last_seen   TEXT NOT NULL,
                event_count INTEGER DEFAULT 0
            )
        """)
        await db.execute("CREATE INDEX IF NOT EXISTS idx_attacker_ip ON events(attacker_ip)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_service ON events(service)")
        await db.execute("CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)")
        await db.commit()


async def store_event(event) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("""
            INSERT INTO events (node_id, timestamp, attacker_ip, attacker_port, service, event_type, data, raw_payload)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            event.node_id, event.timestamp, event.attacker_ip, event.attacker_port,
            event.service, event.event_type, json.dumps(event.data), event.raw_payload
        ))
        # Upsert node record
        await db.execute("""
            INSERT INTO nodes (node_id, last_seen, event_count)
            VALUES (?, ?, 1)
            ON CONFLICT(node_id) DO UPDATE SET last_seen=excluded.last_seen, event_count=event_count+1
        """, (event.node_id, event.timestamp))
        await db.commit()
        return cursor.lastrowid


async def update_event_geo(event_id: int, geo: dict):
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            UPDATE events SET country=?, country_code=?, city=?, lat=?, lon=?, isp=?
            WHERE id=?
        """, (geo.get("country", "Unknown"), geo.get("country_code", "XX"),
              geo.get("city", "Unknown"), geo.get("lat", 0.0),
              geo.get("lon", 0.0), geo.get("isp", "Unknown"), event_id))
        await db.commit()


async def get_recent_events(limit: int = 100) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT * FROM events ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["data"] = json.loads(d["data"] or "{}")
            result.append(d)
        return result


async def get_stats() -> Dict[str, Any]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row

        total = (await (await db.execute("SELECT COUNT(*) as c FROM events")).fetchone())["c"]
        unique_ips = (await (await db.execute("SELECT COUNT(DISTINCT attacker_ip) as c FROM events")).fetchone())["c"]
        unique_nodes = (await (await db.execute("SELECT COUNT(*) as c FROM nodes")).fetchone())["c"]
        total_iocs = (await (await db.execute("SELECT COUNT(*) as c FROM iocs")).fetchone())["c"]

        # Events by service
        svc_rows = await (await db.execute(
            "SELECT service, COUNT(*) as cnt FROM events GROUP BY service ORDER BY cnt DESC"
        )).fetchall()
        by_service = {r["service"]: r["cnt"] for r in svc_rows}

        # Events by event_type
        type_rows = await (await db.execute(
            "SELECT event_type, COUNT(*) as cnt FROM events GROUP BY event_type ORDER BY cnt DESC"
        )).fetchall()
        by_type = {r["event_type"]: r["cnt"] for r in type_rows}

        # Events last 24h
        since = datetime.utcnow().strftime("%Y-%m-%dT%H")
        last_24h = (await (await db.execute(
            "SELECT COUNT(*) as c FROM events WHERE timestamp >= ?", (since,)
        )).fetchone())["c"]

        return {
            "total_events": total,
            "unique_ips": unique_ips,
            "unique_nodes": unique_nodes,
            "total_iocs": total_iocs,
            "events_by_service": by_service,
            "events_by_type": by_type,
            "events_last_24h": last_24h,
        }


async def get_top_attackers(limit: int = 20) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute("""
            SELECT attacker_ip, country, country_code, city, isp,
                   COUNT(*) as hit_count,
                   MAX(timestamp) as last_seen,
                   GROUP_CONCAT(DISTINCT service) as services
            FROM events
            GROUP BY attacker_ip
            ORDER BY hit_count DESC
            LIMIT ?
        """, (limit,))).fetchall()
        return [dict(r) for r in rows]


async def get_iocs(limit: int = 200) -> List[Dict]:
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute("""
            SELECT * FROM iocs ORDER BY hit_count DESC LIMIT ?
        """, (limit,))).fetchall()
        result = []
        for row in rows:
            d = dict(row)
            d["tags"] = json.loads(d["tags"] or "[]")
            result.append(d)
        return result


async def upsert_ioc(ioc_type: str, value: str, confidence: float, tags: List[str]):
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DB_PATH) as db:
        await db.execute("""
            INSERT INTO iocs (ioc_type, value, confidence, tags, first_seen, last_seen, hit_count)
            VALUES (?, ?, ?, ?, ?, ?, 1)
            ON CONFLICT(value) DO UPDATE SET
                hit_count = hit_count + 1,
                last_seen = excluded.last_seen,
                confidence = MAX(confidence, excluded.confidence),
                tags = excluded.tags
        """, (ioc_type, value, confidence, json.dumps(tags), now, now))
        await db.commit()


async def get_ip_event_count(ip: str) -> int:
    async with aiosqlite.connect(DB_PATH) as db:
        row = await (await db.execute(
            "SELECT COUNT(*) as c FROM events WHERE attacker_ip=?", (ip,)
        )).fetchone()
        return row[0]


async def get_geo_map_data(limit: int = 500) -> List[Dict]:
    """Returns lat/lon + counts for map visualization."""
    async with aiosqlite.connect(DB_PATH) as db:
        db.row_factory = aiosqlite.Row
        rows = await (await db.execute("""
            SELECT attacker_ip, lat, lon, country, city, COUNT(*) as cnt
            FROM events
            WHERE lat != 0.0 AND lon != 0.0
            GROUP BY attacker_ip
            ORDER BY cnt DESC
            LIMIT ?
        """, (limit,))).fetchall()
        return [dict(r) for r in rows]
