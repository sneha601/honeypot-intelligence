import httpx
import asyncio
from typing import Dict, List, Any
import database

# Known scanner/researcher organizations
KNOWN_SCANNERS = {
    "shodan", "censys", "shadowserver", "rapid7", "palo alto",
    "internet-wide scan", "masscan", "nmap", "zmap", "binaryedge",
    "greynoise", "leakix", "fofa", "zoomeye"
}

# Geo cache to avoid hammering the free API
_geo_cache: Dict[str, dict] = {}


async def geolocate(ip: str) -> dict:
    """Resolve IP to geolocation using ip-api.com (free, no key required)."""
    if ip in _geo_cache:
        return _geo_cache[ip]

    # Skip private/loopback IPs
    if _is_private(ip):
        return {"country": "Private", "country_code": "XX", "region": "", "city": "Private",
                "lat": 0.0, "lon": 0.0, "isp": "Local", "org": "Local"}

    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            resp = await client.get(
                f"http://ip-api.com/json/{ip}?fields=status,country,countryCode,regionName,city,lat,lon,isp,org"
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("status") == "success":
                    geo = {
                        "country": data.get("country", "Unknown"),
                        "country_code": data.get("countryCode", "XX"),
                        "region": data.get("regionName", "Unknown"),
                        "city": data.get("city", "Unknown"),
                        "lat": data.get("lat", 0.0),
                        "lon": data.get("lon", 0.0),
                        "isp": data.get("isp", "Unknown"),
                        "org": data.get("org", "Unknown"),
                    }
                    _geo_cache[ip] = geo
                    return geo
    except Exception:
        pass

    return {"country": "Unknown", "country_code": "XX", "region": "Unknown",
            "city": "Unknown", "lat": 0.0, "lon": 0.0, "isp": "Unknown", "org": "Unknown"}


async def analyze_event(event) -> Dict[str, Any]:
    """Detect threat patterns and classify the event."""
    tags = []
    threat_level = "low"
    is_known_scanner = False

    # Get geo to check ISP
    geo = _geo_cache.get(event.attacker_ip, {})
    isp_lower = geo.get("isp", "").lower()
    org_lower = geo.get("org", "").lower()

    # Check if known scanner
    for scanner in KNOWN_SCANNERS:
        if scanner in isp_lower or scanner in org_lower:
            is_known_scanner = True
            tags.append("known-scanner")
            break

    # Count how many times this IP has hit us
    hit_count = await database.get_ip_event_count(event.attacker_ip)

    if hit_count >= 50:
        threat_level = "critical"
        tags.append("persistent-attacker")
    elif hit_count >= 20:
        threat_level = "high"
        tags.append("repeated-attacker")
    elif hit_count >= 5:
        threat_level = "medium"
        tags.append("probing")
    else:
        threat_level = "low"

    # Service-specific tagging
    if event.service == "ssh":
        tags.append("ssh-attack")
        if event.event_type == "credential_attempt":
            tags.append("brute-force")
            data = event.data
            if data.get("username") in ("root", "admin", "Administrator", "pi", "ubuntu"):
                tags.append("common-username")
            if data.get("password") in ("", "password", "123456", "admin", "root", "12345"):
                tags.append("weak-password")

    elif event.service == "http":
        tags.append("web-attack")
        path = event.data.get("path", "")
        if any(x in path for x in ("/wp-admin", "/phpmyadmin", "/admin", "/.env", "/config")):
            tags.append("web-scanner")
        if any(x in path for x in ("../", "%2e%2e", "etc/passwd")):
            tags.append("path-traversal")
        if any(x in path for x in ("UNION", "SELECT", "DROP", "OR 1=1")):
            tags.append("sql-injection-attempt")
        ua = event.data.get("user_agent", "").lower()
        if any(x in ua for x in ("sqlmap", "nikto", "masscan", "zgrab", "python-requests")):
            tags.append("scanner-tool")

    elif event.service == "ftp":
        tags.append("ftp-attack")
        if event.event_type == "credential_attempt":
            tags.append("brute-force")

    # Payload analysis
    if event.raw_payload:
        payload = event.raw_payload.lower()
        if any(x in payload for x in ("wget ", "curl ", "/bin/sh", "/bin/bash", "chmod +x")):
            tags.append("malware-download-attempt")
            threat_level = "critical"
        if any(x in payload for x in ("base64", "eval(", "exec(")):
            tags.append("encoded-payload")
            if threat_level not in ("critical",):
                threat_level = "high"

    return {
        "threat_level": threat_level,
        "tags": list(set(tags)),
        "is_known_scanner": is_known_scanner,
        "hit_count": hit_count,
    }


def _is_private(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        a, b = int(parts[0]), int(parts[1])
        if a == 10:
            return True
        if a == 172 and 16 <= b <= 31:
            return True
        if a == 192 and b == 168:
            return True
        if a == 127:
            return True
    except ValueError:
        pass
    return False
