# CnCNet Tunnel Server

A high-performance UDP relay server for Command & Conquer games on CnCNet, supporting V2/V3 tunnel protocols, STUN-based P2P NAT traversal, DDoS protection and a real-time web dashboard.

---

## Table of Contents

1. [Ports](#ports)
2. [Docker](#docker)
3. [Linux (systemd)](#linux-systemd)
4. [Windows](#windows)
5. [Configuration Reference](#configuration-reference)
6. [Web Dashboard](#web-dashboard)

---

## Ports

Open these on your firewall before starting the server.

| Port  | Protocol | Purpose           |
|-------|----------|-------------------|
| 50001 | UDP      | V3 Tunnel         |
| 50000 | TCP+UDP  | V2 Tunnel         |
| 8054  | UDP      | STUN Server       |
| 3478  | UDP      | STUN Server       |
| 1337  | TCP      | Web Dashboard     |

---

## Docker

The recommended setup. Requires [Docker](https://docs.docker.com/engine/install/) with the Compose plugin.

**1. Create a working directory and download the config template:**

```bash
mkdir -p /opt/cncnet && cd /opt/cncnet
curl -O https://raw.githubusercontent.com/Rowtag/cncnet-server/master/appsettings.json
curl -O https://raw.githubusercontent.com/Rowtag/cncnet-server/master/docker-compose.yml
```

**2. Edit the config** — set at minimum `Server.Name` and `Maintenance.Password`:

```bash
nano appsettings.json
```

**3. Start:**

```bash
docker compose up -d
```

**Useful commands:**

```bash
# View logs
docker compose logs -f

# Restart after config change
docker compose restart

# Update to latest image
docker compose pull && docker compose up -d

# Stop
docker compose down
```

**Firewall (UFW):**

```bash
ufw allow 50000/tcp
ufw allow 50000/udp
ufw allow 50001/udp
ufw allow 3478/udp
ufw allow 8054/udp
ufw allow 1337/tcp
```

> **Note:** If using UFW with Docker, ensure `/etc/default/ufw` has `DEFAULT_FORWARD_POLICY="ACCEPT"` and restart Docker after any UFW reload: `systemctl restart docker`

---

## Linux (systemd)

Requires [.NET Runtime 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0).

**1. Install .NET runtime:**

```bash
sudo apt-get update && sudo apt-get install -y dotnet-runtime-10.0
```

**2. Create a dedicated user and install the binary:**

```bash
sudo useradd -m -r cncnet-server

# Download and extract the latest release (adjust filename for your architecture)
sudo unzip cncnet-server-*-linux-x64.zip -d /opt/cncnet-server
sudo chown -R cncnet-server:cncnet-server /opt/cncnet-server
sudo chmod +x /opt/cncnet-server/cncnet-server
```

**3. Edit the config:**

```bash
sudo nano /opt/cncnet-server/appsettings.json
```

**4. Create the systemd service** — save as `/etc/systemd/system/cncnet-server.service`:

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

**5. Enable and start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now cncnet-server

# Follow logs
sudo journalctl -u cncnet-server -f
```

**6. Open firewall ports:**

```bash
sudo ufw allow 50000/tcp
sudo ufw allow 50000/udp
sudo ufw allow 50001/udp
sudo ufw allow 3478/udp
sudo ufw allow 8054/udp
sudo ufw allow 1337/tcp
```

**Updating:**

```bash
sudo systemctl stop cncnet-server
sudo unzip -o cncnet-server-*-linux-x64.zip -d /opt/cncnet-server
sudo systemctl start cncnet-server
```

---

## Windows

Requires [.NET Runtime 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0).

**1. Extract the release archive:**

```powershell
Expand-Archive cncnet-server-*-win-x64.zip -DestinationPath C:\cncnet-server
```

**2. Edit the config:**

```powershell
notepad C:\cncnet-server\appsettings.json
```

**3. Install and start as a Windows Service:**

```powershell
New-Service -Name CnCNetServer `
  -BinaryPathName '"C:\cncnet-server\cncnet-server.exe"' `
  -StartupType Automatic `
  -DisplayName "CnCNet Tunnel Server"

Start-Service CnCNetServer
```

**Useful commands:**

```powershell
# View status
Get-Service CnCNetServer

# Stop / start
Stop-Service CnCNetServer
Start-Service CnCNetServer

# Remove service
Remove-Service CnCNetServer
```

**Updating:**

```powershell
Stop-Service CnCNetServer
Expand-Archive -Force cncnet-server-*-win-x64.zip -DestinationPath C:\cncnet-server
Start-Service CnCNetServer
```

**Firewall:**

```powershell
New-NetFirewallRule -DisplayName "CnCNet" -Direction Inbound -Action Allow `
  -Protocol TCP -LocalPort 50000,1337
New-NetFirewallRule -DisplayName "CnCNet UDP" -Direction Inbound -Action Allow `
  -Protocol UDP -LocalPort 50000,50001,3478,8054
```

---

## Configuration Reference

All settings are read from `appsettings.json` in the working directory.

**Priority order (highest wins):** CLI arguments > Environment variables (`CNCNET_*`) > `appsettings.local.json` > `appsettings.json`

> **Security tip:** Never put passwords in `appsettings.json`. Use `appsettings.local.json` (excluded from version control) or environment variables instead.

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
    "Url": "https://cncnet.org/master-announce",
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
      "https://www.spamhaus.org/drop/edrop.txt",
      "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
      "https://www.binarydefense.com/banlist.txt"
    ]
  },
  "WebMonitor": {
    "Enabled": true,
    "Port": 1337
  },
  "Logging": {
    "LogDirectory": "logs",
    "RetentionDays": 15,
    "RollingIntervalDays": 2,
    "MinimumLevel": "Information"
  }
}
```

**Key settings:**

| Setting | Description |
|---------|-------------|
| `Server.Name` | Server name shown on the master server list |
| `Server.MaxClients` | Maximum simultaneous tunnel clients |
| `Server.ClientTimeout` | Seconds before an idle client is dropped |
| `TunnelV3.IpLimit` | Max connections per IP on V3 (1–40) |
| `TunnelV2.IpLimit` | Max connections per IP on V2 (1–40) |
| `MasterServer.Password` | Password to register on the public master server |
| `Maintenance.Password` | Password to access the web dashboard |
| `Security.IpBlacklistDurationHours` | How long an auto-banned IP stays blocked |

---

## Web Dashboard

Accessible at `http://<your-server>:1337` (port configurable via `WebMonitor.Port`).

Set `Maintenance.Password` in your config to require a login. Leave empty to disable authentication.

**Features:**

| Feature | Description |
|---------|-------------|
| Tunnel status | Connected clients, unique IPs, maintenance mode toggle |
| Security controls | Enable/disable DDoS protection and V3 packet validation |
| Configuration | Adjust IP limits and blacklist duration at runtime |
| Blocked IPs | View and manually unblock entries from the local blacklist |
| Log viewer | Last 50 log messages with level highlighting |

---

## License

GPL-3.0 — see [LICENSE](LICENSE) for details.

## Links

- [CnCNet Website](https://cncnet.org)

---

*made with love by Rowtag*
