# CnCNet Tunnel Server

A high-performance UDP relay server for Command & Conquer games on CnCNet, supporting V2/V3 tunnel protocols, STUN-based P2P NAT traversal, DDoS protection and a real-time web dashboard.

---

## Table of Contents

1. [Ports](#ports)
2. [Docker](#docker)
3. [Linux (systemd)](#linux-systemd)
4. [Windows](#windows)
5. [Matchmaking Server](#matchmaking-server)
6. [Configuration Reference](#configuration-reference)
7. [Web Dashboard](#web-dashboard)

---

## Ports

Open these on your firewall before starting the server.

| Port  | Protocol | Purpose                                  |
|-------|----------|------------------------------------------|
| 50001 | UDP      | V3 Tunnel                                |
| 50000 | TCP+UDP  | V2 Tunnel                                |
| 8054  | UDP      | STUN Server                              |
| 3478  | UDP      | STUN Server                              |
| 1337  | TCP      | Web Dashboard                            |
| 50002 | UDP      | V3 Tunnel — matchmaking ([see below](#matchmaking-server)) |
| 1338  | TCP      | Web Dashboard — matchmaking              |

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

## Matchmaking Server

A matchmaking server is where two clients meet to swap tunnel lists and agree which relay tunnels
to test, before either registers on a relay. That exchange is a few small packets lasting seconds,
so one matchmaking server holds far more clients than a relay — which is the point: it stops every
client having to register on every tunnel just to find a good one.

It **does not carry game traffic**. It relays only the negotiation exchange and drops everything
else. It announces itself to the master list as **version 4**, so clients released before
matchmaking existed ignore it entirely and can never pick it to host a game.

Matchmaking is a mode of the V3 tunnel, and a process has one V3 listener — so a server that does
both roles runs the binary **twice**, from two directories, with two configs.

### Bing

Copy your existing install to a second directory:

```bash
cp -r /opt/cncnet-server /opt/cncnet-server-matchmaking
```

### Bang

Create `/opt/cncnet-server-matchmaking/appsettings.local.json`:

```json
{
  "Server":       { "Name": "Your Server Name (Matchmaking)" },
  "TunnelV3":     { "Enabled": true, "Port": 50002,
                    "Matchmaking": { "Enabled": true, "MaxClients": 2000, "ClientTimeout": 25, "IpLimit": 32 } },
  "TunnelV2":     { "Enabled": false },
  "PeerToPeer":   { "Enabled": false },
  "MasterServer": { "Enabled": true },
  "WebMonitor":   { "Enabled": true, "Port": 1338 },
  "Logging":      { "LogDirectory": "logs-matchmaking" },
  "Maintenance":  { "Password": "your-dashboard-password" }
}
```

Four of those exist to avoid colliding with the first instance, and skipping any will bite you:

| Setting | Why |
|---|---|
| `PeerToPeer: false` | The first instance already holds STUN 8054/3478; binding them again kills startup. |
| `WebMonitor.Port: 1338` | Same, for the dashboard on 1337. |
| `Logging.LogDirectory` | Two processes rolling the same log files fight over locks — and it fails quietly. |
| `TunnelV2: false` | No point running a second V2. |

### Boom

```bash
sed 's/cncnet-server/cncnet-server-matchmaking/g' /etc/systemd/system/cncnet-server.service \
  > /etc/systemd/system/cncnet-server-matchmaking.service
systemctl daemon-reload
systemctl enable --now cncnet-server-matchmaking
```

Open UDP 50002 (and TCP 1338 if you want the dashboard), then confirm it came up in the right role:

```bash
journalctl -u cncnet-server-matchmaking -n 20 | grep "V3 Tunnel started"
# V3 Tunnel started on UDP port 50002 in matchmaking mode (max 2000 clients, 25s timeout, 32 per IP)
```

Within a minute it should appear in <https://cncnet.org/master-list> with a trailing version field
of `4`. If it doesn't, check the log for `heartbeat failed`.

> **Only a handful of servers should run matchmaking.** Every client contacts *all* of them on
> every lobby join, so the set is meant to stay small and stable.

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
| `TunnelV3.RelayPacketCopies` | Copies sent of each relayed packet (1–3). `1` is normal. Above 1 trades upstream bandwidth for loss resilience, and delivers duplicate datagrams to clients — see the note below |
| `TunnelV3.Matchmaking.Enabled` | Run this V3 listener as a [matchmaking server](#matchmaking-server) instead of a game relay |
| `TunnelV3.Matchmaking.MaxClients` | Client limit in matchmaking mode, replacing `Server.MaxClients` |
| `TunnelV3.Matchmaking.ClientTimeout` | Idle timeout in matchmaking mode, replacing `Server.ClientTimeout` |
| `TunnelV3.Matchmaking.IpLimit` | Per-IP limit in matchmaking mode, replacing `TunnelV3.IpLimit` |
| `TunnelV3.Matchmaking.MaxRelayPacketBytes` | Largest packet a matchmaking server will relay |
| `TunnelV2.IpLimit` | Max connections per IP on V2 (1–40) |
| `MasterServer.Password` | Password to register on the public master server |
| `Maintenance.Password` | Password to access the web dashboard |
| `Security.IpBlacklistDurationHours` | How long an auto-banned IP stays blocked |

### A note on packet duplication

`RelayPacketCopies` above `1` is a blunt instrument, and worth understanding before you reach for it:

- It only protects the **server-to-receiver** leg. A packet lost on its way *to* this server is gone
  before duplication happens.
- Copies go out back to back, so it survives a random single drop but not a burst — and congestion
  loses consecutive packets, which is exactly the case it misses.
- It multiplies outbound game bandwidth by that factor, and clients receive duplicate datagrams.
  Client negotiation traffic tolerates duplicates by design; confirm the game itself does before
  enabling it in anger.

It can also be changed live from the dashboard without restarting.

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
