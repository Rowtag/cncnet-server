# CnCNet Tunnel Server

A modern, high-performance UDP relay server for Command & Conquer games on CnCNet.

## Features

- **CnCNet V2 & V3 tunnel protocols** – Full compatibility
- **STUN server** – P2P NAT traversal support
- **Web Dashboard** – Real-time monitoring with login protection
- **DDoS Protection** – Rate limiting, IP blacklists, packet validation
- **External Blacklists** – Auto-loaded from public security sources (refreshed hourly)
- **Cross-platform** – Windows, Linux, macOS

## Ports

| Port  | Protocol | Service       |
|-------|----------|---------------|
| 50001 | UDP      | V3 Tunnel     |
| 50000 | TCP+UDP  | V2 Tunnel     |
| 8054  | UDP      | STUN Server   |
| 3478  | UDP      | STUN Server   |
| 1337  | TCP      | Web Dashboard |

---

## Configuration

All settings live in `appsettings.json`. Edit this file before starting the server.

```json
{
  "Server": {
    "Name": "My CnCNet Server",
    "MaxClients": 200,
    "ClientTimeout": 60
  },
  "TunnelV3": {
    "Enabled": true,
    "Port": 50001,
    "IpLimit": 8,
    "DDoSProtectionEnabled": true
  },
  "TunnelV2": {
    "Enabled": true,
    "Port": 50000,
    "IpLimit": 4,
    "DDoSProtectionEnabled": true
  },
  "PeerToPeer": {
    "Enabled": true,
    "StunPort1": 8054,
    "StunPort2": 3478
  },
  "MasterServer": {
    "Enabled": true,
    "Url": "http://cncnet.org/master-announce",
    "Password": "",
    "AnnounceIntervalSeconds": 60
  },
  "Maintenance": {
    "Password": ""
  },
  "Security": {
    "IpBlacklistDurationHours": 24,
    "MaxPingsPerIp": 20,
    "MaxPingsGlobal": 5000,
    "ExternalBlacklistUrls": [
      "https://www.spamhaus.org/drop/drop.txt",
      "https://www.spamhaus.org/drop/edrop.txt"
    ]
  },
  "WebMonitor": {
    "Enabled": true,
    "Port": 1337
  },
  "Logging": {
    "LogDirectory": "logs",
    "RetentionDays": 15,
    "MinimumLevel": "Information"
  }
}
```

---

## Installation

Download the latest release from the [Releases page](https://github.com/Rowtag/cncnet-server/releases/latest).

### Linux (systemd)

**Requirements:** [.NET Runtime 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)

```bash
# Install .NET runtime
sudo apt-get update && sudo apt-get install -y dotnet-runtime-10.0

# Create dedicated user
sudo useradd -m -r cncnet-server

# Extract the release archive (replace filename with the one you downloaded)
sudo unzip cncnet-server-*-linux-x64.zip -d /opt/cncnet-server
sudo chown -R cncnet-server:cncnet-server /opt/cncnet-server
sudo chmod +x /opt/cncnet-server/cncnet-server

# Edit config
sudo nano /opt/cncnet-server/appsettings.json
```

Create `/etc/systemd/system/cncnet-server.service`:

```ini
[Unit]
Description=CnCNet Tunnel Server
After=network.target

[Service]
Type=simple
User=cncnet-server
WorkingDirectory=/opt/cncnet-server
ExecStart=/opt/cncnet-server/cncnet-server
Restart=always
RestartSec=5
KillSignal=SIGINT

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cncnet-server

# Follow logs
sudo journalctl -u cncnet-server -f
```

Open firewall ports:

```bash
sudo ufw allow 50000/tcp
sudo ufw allow 50000/udp
sudo ufw allow 50001/udp
sudo ufw allow 3478/udp
sudo ufw allow 8054/udp
sudo ufw allow 1337/tcp
```

---

### Windows

**Requirements:** [.NET Runtime 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)

```powershell
# Extract the release archive
Expand-Archive cncnet-server-*-win-x64.zip -DestinationPath C:\cncnet-server

# Edit config
notepad C:\cncnet-server\appsettings.json

# Install and start as Windows Service
New-Service -Name CnCNetServer `
  -BinaryPathName '"C:\cncnet-server\cncnet-server.exe"' `
  -StartupType Automatic `
  -DisplayName "CnCNet Tunnel Server"

Start-Service CnCNetServer
```

---

### Docker

```bash
# 1. Download the config template
curl -O https://raw.githubusercontent.com/Rowtag/cncnet-server/master/appsettings.json

# 2. Edit the config
nano appsettings.json

# 3. Download docker-compose.yml
curl -O https://raw.githubusercontent.com/Rowtag/cncnet-server/master/docker-compose.yml

# 4. Start
docker compose up -d

# Follow logs
docker compose logs -f
```

After changing `appsettings.json`:

```bash
docker compose restart
```

---

## Web Dashboard

Available at `http://<server>:1337` (port configurable via `WebMonitor.Port`).

Protect the dashboard by setting a password via `Maintenance.Password` in `appsettings.json`.

**Features:**
- Tunnel status & connected clients
- DDoS protection & packet validation toggles
- Maintenance mode per tunnel
- IP limit & blacklist duration configuration
- Blocked IP management with manual unblock
- Real-time log viewer

---

## License

GPL-3.0 – See [LICENSE](LICENSE) for details.

## Links

- [CnCNet Website](https://cncnet.org)

---

*made with love by Rowtag*
