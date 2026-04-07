# Deployment Guide — Fly.io (Free, No Credit Card)

## Prerequisites

Install flyctl (Fly.io CLI):

**Windows (PowerShell):**
```powershell
iwr https://fly.io/install.ps1 -useb | iex
```

**Mac/Linux:**
```bash
curl -L https://fly.io/install.sh | sh
```

Then sign up for free:
```bash
fly auth signup
```
> Use your email — no credit card required for the free tier.

---

## Step 1 — Deploy the Central Server

```bash
cd central-server

# First-time setup (follow the prompts, choose "No" to Postgres/Redis)
fly launch --config fly.toml

# Create persistent volume for SQLite DB (1GB free)
fly volumes create honeynet_data --size 1 --region sin

# Deploy
fly deploy
```

Note the URL it gives you — it will look like:
`https://honeynet-central.fly.dev`

---

## Step 2 — Deploy the Honeypot Node

```bash
cd ../honeypot-node

# Tell the node where the central server is
fly secrets set CENTRAL_SERVER=https://honeynet-central.fly.dev

# First-time setup
fly launch --config fly.toml

# Deploy
fly deploy
```

---

## Step 3 — Open the Dashboard

Go to: `https://honeynet-central.fly.dev`

Within minutes (sometimes seconds) you'll see SSH and Telnet bots hitting the node.

---

## Step 4 — Add a Second Node (Optional but Powerful)

Deploy the same honeypot-node in a different region to catch geographically distributed attackers.

```bash
cd honeypot-node

# Create a second app with a different name and region
fly launch --config fly.toml --name honeynet-node-02 --region iad   # Washington DC

fly secrets set CENTRAL_SERVER=https://honeynet-central.fly.dev \
               NODE_ID=node-iad-02 \
               --app honeynet-node-02

fly deploy --app honeynet-node-02
```

---

## Useful Commands

```bash
# View live logs from the node
fly logs --app honeynet-node-01

# View live logs from central server
fly logs --app honeynet-central

# SSH into a machine (for debugging)
fly ssh console --app honeynet-central

# Check machine status
fly status --app honeynet-node-01

# Export IP blocklist
curl https://honeynet-central.fly.dev/api/export/blocklist

# Export YARA rules
curl https://honeynet-central.fly.dev/api/export/yara
```

---

## Free Tier Limits

| Resource       | Free Allowance          |
|----------------|------------------------|
| Machines       | 3 shared-cpu-1x VMs    |
| RAM            | 256 MB each            |
| Volume storage | 3 GB total             |
| Outbound data  | 160 GB/month           |

This project uses 2 machines (central + 1 node), well within free limits.

---

## Ports Exposed on the Node

| Port | Service | What it catches                    |
|------|---------|-------------------------------------|
| 22   | SSH     | Brute-force bots, credential stuffing |
| 23   | Telnet  | Mirai botnet, IoT scanners          |
| 21   | FTP     | Brute-force, anonymous access probes |
| 80   | HTTP    | Web scanners, WordPress/phpMyAdmin exploits |
