# CnCNet Tunnel Server v4.1

A modern, high-performance UDP relay server for Command & Conquer games on CnCNet.

---

## Features

- **Cross-platform** - Windows, Linux, macOS
- **CnCNet V2 & V3 tunnel protocols** - Full compatibility
- **STUN server** - P2P NAT traversal support
- **Web Dashboard** - Real-time monitoring with login protection
- **DDoS Protection** - Rate limiting, IP blacklists, packet validation
- **Runtime Configuration** - Adjust settings via web interface
- **GDPR Compliant** - IP anonymization in logs, privacy by design

---

## Requirements

- [.NET Runtime 10](https://dotnet.microsoft.com/en-us/download/dotnet/10.0/runtime)

---

## Ports

Make sure these ports are open/forwarded:

| Port | Protocol | Service |
|------|----------|---------|
| 50001 | UDP | V3 Tunnel |
| 50000 | TCP + UDP | V2 Tunnel |
| 8054 | UDP | STUN Server |
| 3478 | UDP | STUN Server |
| 1337 | TCP | Web Dashboard |

---

## Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-n, --name <name>` | Server name shown in server list | - |
| `-p, --port <port>` | V3 tunnel port (UDP) | 50001 |
| `-pv2, --portv2 <port>` | V2 tunnel port (HTTP+UDP) | 50000 |
| `-m, --maxclients <n>` | Maximum clients allowed | 200 |
| `-t, --timeout <sec>` | Client timeout in seconds | 60 |
| `-l, --iplimit <n>` | Max clients per IP (V3) | 8 |
| `-iplv2, --iplimitv2 <n>` | Max requests per IP (V2) | 8 |
| `--nomaster` | Don't register to master server | - |
| `-mpw, --maintpw <pw>` | Admin password for web dashboard | - |
| `--nop2p` | Disable STUN servers | - |
| `--nostatus` | Disable web dashboard | - |
| `--statusport <port>` | Web dashboard port | 1337 |
| `--logdir <path>` | Log directory | logs |
| `-v, --verbose` | Enable verbose logging | - |
| `-h, --help` | Show help | - |

---

## Quick Start

Run directly from source:

```bash
dotnet run -- --name "My Server" --nomaster --maintpw "yourpassword"
```

---

## Web Dashboard

Access at `http://your-server-ip:1337`

Login with the password set via `--maintpw`.

**Features:**
- Server status overview
- Connected clients statistics
- Blocked IPs management with unblock
- Maintenance mode toggles (V2/V3)
- IP-Limit and Blacklist duration settings
- Real-time log viewer (last 50 entries)

---

## Installation

### Windows

**1. Download and extract:**

```powershell
Expand-Archive cncnet-server-win-x64.zip -DestinationPath C:\cncnet-server
```

**2. Create Windows Service:**

```powershell
New-Service -Name "CnCNetServer" -BinaryPathName '"C:\cncnet-server\cncnet-server.exe" --name "My Server" --maintpw "yourpassword"' -StartupType Automatic -DisplayName "CnCNet Tunnel Server"
```

**3. Start the service:**

```powershell
Start-Service CnCNetServer
```

**Manage the service:**

```powershell
# Stop
Stop-Service CnCNetServer

# Restart
Restart-Service CnCNetServer

# Remove
Stop-Service CnCNetServer
sc.exe delete CnCNetServer
```

---

### Linux

**1. Install .NET Runtime:**

```bash
sudo apt-get update && sudo apt-get install -y dotnet-runtime-10.0
```

**2. Create user and directory:**

```bash
sudo useradd -r -m -d /home/cncnet-server -s /bin/false cncnet-server
```

**3. Extract and set permissions:**

```bash
sudo unzip cncnet-server-linux-x64.zip -d /home/cncnet-server
sudo chown -R cncnet-server:cncnet-server /home/cncnet-server
sudo chmod +x /home/cncnet-server/cncnet-server
```

**4. Create systemd service file:**

```bash
sudo nano /etc/systemd/system/cncnet-server.service
```

Paste this content:

```ini
[Unit]
Description=CnCNet Tunnel Server
After=network.target

[Service]
Type=simple
User=cncnet-server
WorkingDirectory=/home/cncnet-server
ExecStart=/home/cncnet-server/cncnet-server --name "My Server" --maintpw "yourpassword"
Restart=always
RestartSec=5
KillSignal=SIGINT
Environment=DOTNET_ENVIRONMENT=Production

[Install]
WantedBy=multi-user.target
```

Save with `Ctrl+O`, `Enter`, `Ctrl+X`.

**5. Enable and start:**

```bash
sudo systemctl daemon-reload
sudo systemctl enable cncnet-server
sudo systemctl start cncnet-server
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

---

### Useful Commands

```bash
# Check status
sudo systemctl status cncnet-server

# View live logs
sudo journalctl -u cncnet-server -f

# Restart server
sudo systemctl restart cncnet-server

# Stop server
sudo systemctl stop cncnet-server
```

---

## Logging

Logs are written to the `logs/` directory with automatic rolling and retention.

---

## Privacy & GDPR

This server is designed with privacy in mind:

- **IP Anonymization** - IP addresses are masked in all log files (last octet for IPv4, last 80 bits for IPv6)
- **No Personal Data** - Only technical connection data required for operation is processed
- **Minimal Retention** - In-memory logs are limited to 1000 entries, file logs rotate automatically
- **Security Blacklists** - Blocked IPs are stored in full for DDoS protection (legitimate interest under GDPR Art. 6(1)(f))

---

## License

This project is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

You are free to use, modify, and distribute this software under the terms of the GPL v3. Any derivative works must also be released under GPL v3.

See [LICENSE](LICENSE) file for the full license text.

---

## Credits

This project is based on the original [CnCNet Tunnel Server](https://github.com/CnCNet/cncnet-server).

**Contributors:**
- [FunkyFr3sh](https://github.com/FunkyFr3sh) - Original author
- [GrantBartlett](https://github.com/GrantBartlett) - Contributor
- [Rowtag](https://github.com/Starter2007) - v4.0 rewrite & modernization

---

## Links

- [CnCNet Website](https://cncnet.org)
- [Original Repository](https://github.com/CnCNet/cncnet-server)
