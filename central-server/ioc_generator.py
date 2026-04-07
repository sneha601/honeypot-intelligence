import hashlib
import json
from datetime import datetime
from typing import List, Dict
import database

# Thresholds for auto-promoting IPs to IOC list
BRUTE_FORCE_THRESHOLD = 10   # 10+ credential attempts → IOC
MULTI_SERVICE_THRESHOLD = 3  # hitting 3+ services → IOC
PAYLOAD_THRESHOLD = 1        # any payload drop → instant IOC


async def check_and_generate(ip: str) -> List[Dict]:
    """Check if IP qualifies for IOC promotion and generate IOC entries."""
    generated = []
    count = await database.get_ip_event_count(ip)

    if count >= BRUTE_FORCE_THRESHOLD:
        confidence = min(0.5 + (count / 100), 0.99)
        tags = ["brute-force", "auto-generated"]
        if count >= 50:
            tags.append("high-volume")
        await database.upsert_ioc("ip", ip, confidence, tags)
        generated.append({"ioc_type": "ip", "value": ip, "confidence": confidence, "tags": tags})

    return generated


async def generate_payload_ioc(payload: str, ip: str) -> Dict:
    """Generate a hash-based IOC from a dropped payload."""
    payload_hash = hashlib.sha256(payload.encode()).hexdigest()
    tags = ["payload", "auto-generated", f"source-ip:{ip}"]
    await database.upsert_ioc("sha256", payload_hash, 0.9, tags)
    return {"ioc_type": "sha256", "value": payload_hash, "confidence": 0.9, "tags": tags}


async def export_blocklist() -> str:
    """Export all high-confidence IP IOCs as a plain text blocklist."""
    iocs = await database.get_iocs(limit=10000)
    lines = [
        "# Honeypot Intelligence Network — IP Blocklist",
        f"# Generated: {datetime.utcnow().isoformat()}Z",
        "# Format: one IP per line",
        "",
    ]
    for ioc in iocs:
        if ioc["ioc_type"] == "ip" and ioc["confidence"] >= 0.6:
            lines.append(ioc["value"])
    return "\n".join(lines)


async def export_yara_rule() -> str:
    """Generate a basic YARA rule from collected payload hashes."""
    iocs = await database.get_iocs(limit=10000)
    hashes = [ioc["value"] for ioc in iocs if ioc["ioc_type"] == "sha256"]
    if not hashes:
        return "// No payload IOCs collected yet"

    hash_conditions = "\n        ".join([f'hash.sha256(0, filesize) == "{h}"' for h in hashes[:50]])
    rule = f"""import "hash"

rule HoneypotIntelligence_Payloads {{
    meta:
        description = "Payloads collected by Honeypot Intelligence Network"
        generated   = "{datetime.utcnow().isoformat()}Z"
        author      = "HoneyNet Auto-Generator"
    condition:
        {hash_conditions}
}}
"""
    return rule
