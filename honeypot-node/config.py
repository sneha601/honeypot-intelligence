import os

# Identity of this node — set via environment variable or default
NODE_ID = os.getenv("NODE_ID", "node-local-01")

# Central server URL
CENTRAL_SERVER = os.getenv("CENTRAL_SERVER", "http://localhost:8000")

# Ports the honeypot listens on (use high ports locally; map to 22/21/80 in Docker)
SSH_PORT    = int(os.getenv("SSH_PORT",    "2222"))
FTP_PORT    = int(os.getenv("FTP_PORT",    "2121"))
HTTP_PORT   = int(os.getenv("HTTP_PORT",   "8080"))
TELNET_PORT = int(os.getenv("TELNET_PORT", "2323"))

# SSH banner shown to connecting clients
SSH_BANNER = os.getenv("SSH_BANNER", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6")

# FTP banner
FTP_BANNER = os.getenv("FTP_BANNER", "220 ProFTPD 1.3.5e Server (Debian) [::ffff:127.0.0.1]")
