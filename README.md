# CnCNet Tunnel Server v4.0

A modern, high-performance UDP relay server for Command & Conquer games on CnCNet.

## Features

- **.NET 10** - Latest .NET runtime for best performance
- **Cross-platform** - Windows, Linux, macOS
- **No admin privileges required** - Runs as standard user
- **CnCNet V2 & V3 tunnel protocols** - Full compatibility
- **STUN server** - P2P NAT traversal support
- **Web Dashboard** - Real-time monitoring with login protection
- **DDoS Protection** - Rate limiting, IP blacklists, packet validation
- **External Blacklists** - Auto-loaded from public security sources
- **Runtime Configuration** - Adjust settings via web interface
- **Serilog Logging** - Rolling log files with configurable retention

## Requirements

- [.NET Runtime 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0/runtime)

## Ports

Make sure these ports are open/forwarded (default configuration):

| Port | Protocol | Service |
|------|----------|---------|
| 50001 | UDP | V3 Tunnel |
| 50000 | TCP+UDP | V2 Tunnel |
| 8054 | UDP | STUN Server |
| 3478 | UDP | STUN Server |
| 1337 | TCP | Web Dashboard (localhost only) |

## Command Line Options

```
Options:
  --name, -n <name>       Server name shown in server list
  --port, -p <port>       V3 tunnel port (UDP) [default: 50001]
  --portv2 <port>         V2 tunnel port (HTTP+UDP) [default: 50000]
  --maxclients, -m <n>    Maximum clients allowed [default: 200]
  --timeout, -t <sec>     Client timeout in seconds [default: 60]
  --iplimit, -l <n>       Max clients per IP (V3) [default: 8, max: 40]
  --iplimitv2 <n>         Max requests per IP (V2) [default: 8, max: 40]
  --nomaster              Don't register to master server
  --maintpw <pw>          Admin password (required for web dashboard)
  --nop2p                 Disable STUN servers
  --nostatus              Disable web dashboard
  --statusport <port>     Web dashboard port [default: 1337]
  --logdir <path>         Log directory [default: "logs"]
  --verbose, -v           Enable verbose logging
  --help, -h              Show help
```

## Quick Start

### Run from Console

```bash
# Start server (without master server registration)
dotnet run -- --name "My Server" --nomaster --maintpw "yourpassword"
```

### Web Dashboard

The dashboard is available at `http://localhost:1337` and requires login with the `--maintpw` password.

Features:
- Tunnel status overview
- Connected clients statistics
- Security settings (toggles)
- Blocked IPs management
- Real-time log viewer
- Maintenance mode per tunnel

## Installation

### Windows Service (PowerShell)

```powershell
# Download and extract
Expand-Archive cncnet-server-win-x64.zip -DestinationPath C:\cncnet-server

# Create service
New-Service -Name CnCNetServer `
  -BinaryPathName '"C:\cncnet-server\cncnet-server.exe" --name "MyServer" --nomaster --maintpw "admin"' `
  -StartupType Automatic `
  -DisplayName "CnCNet Tunnel Server"

# Start service
Start-Service CnCNetServer
```

### Linux Daemon (systemd)

```bash
# Install .NET runtime
sudo apt-get update
sudo apt-get install -y dotnet-runtime-10.0

# Create user and extract
sudo useradd -m cncnet-server
sudo unzip cncnet-server-linux-x64.zip -d /home/cncnet-server
sudo chown -R cncnet-server:cncnet-server /home/cncnet-server
sudo chmod +x /home/cncnet-server/cncnet-server
```

Create `/etc/systemd/system/cncnet-server.service`:

```ini
[Unit]
Description=CnCNet Tunnel Server v4.0
After=network.target

[Service]
Type=notify
User=cncnet-server
WorkingDirectory=/home/cncnet-server
ExecStart=/home/cncnet-server/cncnet-server --name "MyServer" --nomaster --maintpw "admin"
Restart=always
RestartSec=5
KillSignal=SIGINT
Environment=DOTNET_ENVIRONMENT=Production

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start
sudo systemctl daemon-reload
sudo systemctl enable cncnet-server
sudo systemctl start cncnet-server

# Open firewall ports
sudo ufw allow 50000/tcp
sudo ufw allow 50000/udp
sudo ufw allow 50001/udp
sudo ufw allow 3478/udp
sudo ufw allow 8054/udp

# View logs
sudo journalctl -u cncnet-server -f
```

## Logging

Logs are written to the `logs/` directory with configurable rolling and retention.

## License

MIT License - See LICENSE file for details.

## Links

- [CnCNet Website](https://cncnet.org)

---
*made with love by Rowtag*
