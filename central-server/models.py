from pydantic import BaseModel, Field
from typing import Optional, Dict, Any, List
from datetime import datetime


class AttackEvent(BaseModel):
    node_id: str
    timestamp: str = Field(default_factory=lambda: datetime.utcnow().isoformat())
    attacker_ip: str
    attacker_port: int
    service: str           # ssh, http, ftp, telnet
    event_type: str        # credential_attempt, command_executed, payload_dropped, scan_probe
    data: Dict[str, Any] = {}
    raw_payload: Optional[str] = None


class GeoInfo(BaseModel):
    country: str = "Unknown"
    country_code: str = "XX"
    region: str = "Unknown"
    city: str = "Unknown"
    lat: float = 0.0
    lon: float = 0.0
    isp: str = "Unknown"
    org: str = "Unknown"


class IOC(BaseModel):
    ioc_type: str          # ip, hash, domain, useragent
    value: str
    confidence: float      # 0.0 - 1.0
    tags: List[str] = []
    first_seen: str
    last_seen: str
    hit_count: int = 1


class ThreatSummary(BaseModel):
    threat_level: str      # low, medium, high, critical
    tags: List[str] = []
    campaign_id: Optional[str] = None
    is_known_scanner: bool = False
