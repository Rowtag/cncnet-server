# CnCNet Tunnel Server v4.1

A modern, high-performance UDP relay server for Command & Conquer games on CnCNet.

## Features

- **.NET 10** – Latest .NET runtime for best performance
- **Cross-platform** – Windows, Linux, macOS
- **CnCNet V2 & V3 tunnel protocols** – Full compatibility
- **STUN server** – P2P NAT traversal support
- **Web Dashboard** – Real-time monitoring with login protection
- **DDoS Protection** – Rate limiting, IP blacklists, packet validation
- **External Blacklists** – Auto-loaded from public security sources (refreshed hourly)
- **Runtime Configuration** – Adjust settings via web interface
- **Layered Configuration** – JSON files, environment variables, CLI arguments

## Requirements

- [.NET Runtime 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0)

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

Configuration is layered – higher layers override lower ones:

```
1. appsettings.json        Base configuration
2. appsettings.local.json  Local overrides (passwords, server name)
3. Environment variables   Recommended for production / Docker
4. CLI arguments           Quick overrides
```

### appsettings.json

The base configuration file with sensible defaults:

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

### appsettings.local.json

Copy `appsettings.local.example.json` to `appsettings.local.json` and fill in your values.
Only include the settings you want to override:

```json
{
  "Server": {
    "Name": "My CnCNet Server"
  },
  "Maintenance": {
    "Password": "your-password"
  },
  "MasterServer": {
    "Enabled": false
  }
}
```

### Environment Variables

Prefix all variables with `CNCNET_` and use `__` for nested keys:

```bash
CNCNET_SERVER__NAME="My CnCNet Server"
CNCNET_SERVER__MAXCLIENTS=200
CNCNET_MAINTENANCE__PASSWORD=your-password
CNCNET_MASTERSERVER__PASSWORD=master-password
CNCNET_TUNNELV3__PORT=50001
CNCNET_TUNNELV2__PORT=50000
CNCNET_WEBMONITOR__PORT=1337
```

### CLI Arguments

```
--name, -n <n>         Server name
--maxclients, -m <n>      Maximum clients (default: 200)
--timeout, -t <sec>       Client timeout in seconds (default: 60)
--port, -p <port>         V3 tunnel UDP port (default: 50001)
--iplimit, -l <n>         Max clients per IP for V3 (default: 8)
--portv2 <port>           V2 tunnel port (default: 50000)
--iplimitv2 <n>           Max requests per IP for V2 (default: 4)
--nop2p                   Disable STUN/P2P servers
--nomaster                Don't register to master server
--master <url>            Master server URL
--masterpw <pw>           Master server password
--maintpw <pw>            Web dashboard password
--nostatus                Disable web dashboard
--statusport <port>       Web dashboard port (default: 1337)
--logdir <path>           Log directory (default: logs)
--verbose, -v             Enable debug logging
--help, -h                Show help
```

---

## Quick Start

### 1. Edit the local config

```bash
cp appsettings.local.example.json appsettings.local.json
nano appsettings.local.json
```

### 2. Run

```bash
dotnet run
```

### 3. With CLI overrides

```bash
dotnet run -- --name "TestServer" --nomaster --verbose
```

---

## Installation

### Linux Daemon (systemd)

```bash
# Install .NET runtime
sudo apt-get update && sudo apt-get install -y dotnet-runtime-10.0

# Create dedicated user
sudo useradd -m -r cncnet-server

# Extract binary
sudo unzip cncnet-server-linux-x64.zip -d /opt/cncnet-server
sudo chown -R cncnet-server:cncnet-server /opt/cncnet-server
sudo chmod +x /opt/cncnet-server/cncnet-server

# Setup local config
sudo -u cncnet-server cp /opt/cncnet-server/appsettings.local.example.json \
                         /opt/cncnet-server/appsettings.local.json
sudo -u cncnet-server nano /opt/cncnet-server/appsettings.local.json
```

Create `/etc/systemd/system/cncnet-server.service`:

```ini
[Unit]
Description=CnCNet Tunnel Server v4.1
After=network.target

[Service]
Type=notify
User=cncnet-server
WorkingDirectory=/opt/cncnet-server
ExecStart=/opt/cncnet-server/cncnet-server
Restart=always
RestartSec=5
KillSignal=SIGINT
Environment=DOTNET_ENVIRONMENT=Production

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cncnet-server
sudo journalctl -u cncnet-server -f
```

**Open firewall ports:**

```bash
sudo ufw allow 50000/tcp
sudo ufw allow 50000/udp
sudo ufw allow 50001/udp
sudo ufw allow 3478/udp
sudo ufw allow 8054/udp
sudo ufw allow 1337/tcp
```

### Windows Service

```powershell
Expand-Archive cncnet-server-win-x64.zip -DestinationPath C:\cncnet-server

Copy-Item C:\cncnet-server\appsettings.local.example.json `
          C:\cncnet-server\appsettings.local.json
notepad C:\cncnet-server\appsettings.local.json

New-Service -Name CnCNetServer `
  -BinaryPathName '"C:\cncnet-server\cncnet-server.exe"' `
  -StartupType Automatic -DisplayName "CnCNet Tunnel Server"

Start-Service CnCNetServer
```

### Docker

```bash
# 1. Copy and edit the environment file
cp .env.example .env
nano .env

# 2. Start
docker compose up -d

# 3. View logs
docker compose logs -f
```

The `.env` file is automatically loaded by docker-compose.
Logs are persisted in the `./logs` directory on the host.

---

## Web Dashboard

Available at `http://<server>:<statusport>` (default port 1337).

**Features:**
- Login with maintenance password
- Tunnel status & connected clients
- Security toggles (DDoS protection, packet validation)
- Maintenance mode per tunnel
- IP limit configuration
- Blocked IP management
- Real-time log viewer
- Auto-refresh every 5 seconds

---

## Logging

Logs are written to the `logs/` directory with rolling files and configurable retention.
The web dashboard shows the last 50 log entries in real time.

---

## License

GPL-3.0 – See LICENSE file for details.

## Links

- [CnCNet Website](https://cncnet.org)

---

*made with love by Rowtag*
