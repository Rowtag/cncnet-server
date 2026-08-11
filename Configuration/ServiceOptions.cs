namespace CnCNetServer.Configuration;

/// <summary>
/// Root configuration options for the CnCNet tunnel server.
/// Maps to the appsettings.json structure.
/// </summary>
public sealed class ServiceOptions
{
    public ServerOptions Server { get; set; } = new();
    public TunnelV3Options TunnelV3 { get; set; } = new();
    public TunnelV2Options TunnelV2 { get; set; } = new();
    public PeerToPeerOptions PeerToPeer { get; set; } = new();
    public MasterServerOptions MasterServer { get; set; } = new();
    public MaintenanceOptions Maintenance { get; set; } = new();
    public SecurityOptions Security { get; set; } = new();
    public WebMonitorOptions WebMonitor { get; set; } = new();
    public LoggingOptions Logging { get; set; } = new();
}

/// <summary>
/// General server configuration options.
/// </summary>
public sealed class ServerOptions
{
    /// <summary>
    /// Display name of the server shown in the master server list.
    /// </summary>
    public string Name { get; set; } = "Unnamed server";

    /// <summary>
    /// Maximum number of concurrent clients allowed on this tunnel server.
    /// </summary>
    public int MaxClients { get; set; } = 200;

    /// <summary>
    /// Timeout in seconds after which inactive clients are disconnected.
    /// </summary>
    public int ClientTimeout { get; set; } = 60;
}

/// <summary>
/// Configuration for the V3 tunnel (UDP-only, modern protocol).
/// </summary>
public sealed class TunnelV3Options
{
    /// <summary>
    /// Whether the V3 tunnel is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// UDP port for the V3 tunnel server.
    /// </summary>
    public int Port { get; set; } = 50001;

    /// <summary>
    /// Maximum number of connections allowed per IP address (1-40).
    /// </summary>
    public int IpLimit { get; set; } = 8;

    /// <summary>
    /// Whether DDoS protection is enabled for V3 tunnel.
    /// </summary>
    public bool DDoSProtectionEnabled { get; set; } = true;

    /// <summary>
    /// How many copies of each relayed packet to send. 1 means send once, which is normal
    /// behaviour; 2 or more sends duplicates, trading upstream bandwidth for resilience to packet
    /// loss.
    /// </summary>
    public int RelayPacketCopies { get; set; } = 1;

    /// <summary>
    /// Settings for running this server in the matchmaking role.
    /// </summary>
    public MatchmakingOptions Matchmaking { get; set; } = new();
}

/// <summary>
/// Configuration for the matchmaking role of the V3 tunnel.
/// </summary>
/// <remarks>
/// A matchmaking server is where two clients meet to swap tunnel lists and agree which relay
/// tunnels to test, before either registers on a relay. That exchange is a handful of small packets
/// lasting seconds, so one matchmaking server carries far more clients than a relay - which is the
/// point: it lets every pair pick good tunnels without first registering on every tunnel.
///
/// It relays only that exchange and drops game traffic. It announces itself to the master list as
/// version 4, so clients that predate matchmaking ignore it and cannot pick it to host a game.
/// </remarks>
public sealed class MatchmakingOptions
{
    /// <summary>
    /// Whether this server runs as a matchmaking server instead of an ordinary V3 relay.
    /// </summary>
    public bool Enabled { get; set; }

    /// <summary>
    /// Maximum concurrent clients in the matchmaking role, replacing <see cref="ServerOptions.MaxClients"/>.
    /// Sessions here are short and hold no game state, so this is far higher than a relay's limit.
    /// </summary>
    public int MaxClients { get; set; } = 2000;

    /// <summary>
    /// Timeout in seconds after which an inactive matchmaking client is dropped, replacing
    /// <see cref="ServerOptions.ClientTimeout"/>. Clients are here only for the few seconds an
    /// exchange takes, so a relay's timeout would tie up most of the capacity on finished sessions.
    /// </summary>
    public int ClientTimeout { get; set; } = 25;

    /// <summary>
    /// Maximum concurrent sessions per IP in the matchmaking role, replacing
    /// <see cref="TunnelV3Options.IpLimit"/>. Higher than a relay's, because every player passes
    /// through matchmaking for every lobby they join: a shared connection, or one player moving
    /// between lobbies, legitimately produces far more sessions here than on any one relay.
    /// </summary>
    public int IpLimit { get; set; } = 32;

    /// <summary>
    /// Largest packet, in bytes, that will be relayed between matchmaking clients. Tunnel list
    /// exchanges are under a kilobyte; anything larger is not matchmaking traffic.
    /// </summary>
    public int MaxRelayPacketBytes { get; set; } = 1200;
}

/// <summary>
/// Configuration for the V2 tunnel (HTTP+UDP, legacy protocol).
/// </summary>
public sealed class TunnelV2Options
{
    /// <summary>
    /// Whether the V2 tunnel is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// Port for the V2 tunnel server (HTTP and UDP).
    /// </summary>
    public int Port { get; set; } = 50000;

    /// <summary>
    /// Maximum number of game requests allowed per IP address (1-40).
    /// </summary>
    public int IpLimit { get; set; } = 8;

    /// <summary>
    /// Whether DDoS protection is enabled for V2 tunnel.
    /// </summary>
    public bool DDoSProtectionEnabled { get; set; } = true;
}

/// <summary>
/// Configuration for the peer-to-peer STUN server.
/// </summary>
public sealed class PeerToPeerOptions
{
    /// <summary>
    /// Whether P2P NAT traversal (STUN) is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// First STUN UDP port.
    /// </summary>
    public int StunPort1 { get; set; } = 8054;

    /// <summary>
    /// Second STUN UDP port.
    /// </summary>
    public int StunPort2 { get; set; } = 3478;
}

/// <summary>
/// Configuration for master server registration.
/// </summary>
public sealed class MasterServerOptions
{
    /// <summary>
    /// Whether to announce this server to the master server.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// URL of the CnCNet master server.
    /// </summary>
    public string Url { get; set; } = "http://cncnet.org/master-announce";

    /// <summary>
    /// Password for master server registration.
    /// </summary>
    public string Password { get; set; } = string.Empty;

    /// <summary>
    /// Interval in seconds between master server announcements.
    /// </summary>
    public int AnnounceIntervalSeconds { get; set; } = 60;
}

/// <summary>
/// Configuration for maintenance mode.
/// </summary>
public sealed class MaintenanceOptions
{
    /// <summary>
    /// Password required to toggle maintenance mode.
    /// </summary>
    public string Password { get; set; } = string.Empty;
}

/// <summary>
/// Security and DDoS protection configuration (shared settings).
/// </summary>
public sealed class SecurityOptions
{
    /// <summary>
    /// Duration in hours to keep an IP in the local blacklist (1-168).
    /// </summary>
    public int IpBlacklistDurationHours { get; set; } = 8;

    /// <summary>
    /// Maximum ping requests allowed per IP per heartbeat interval.
    /// </summary>
    public int MaxPingsPerIp { get; set; } = 20;

    /// <summary>
    /// Maximum total ping requests allowed globally per heartbeat interval.
    /// </summary>
    public int MaxPingsGlobal { get; set; } = 5000;

    /// <summary>
    /// URLs of external IP blacklists to load (DDoS, bots, scanners).
    /// Loaded on startup and refreshed hourly.
    /// </summary>
    public string[] ExternalBlacklistUrls { get; set; } =
    [
        // Spamhaus DROP (Don't Route Or Peer) - known hijacked/spam networks
        "https://www.spamhaus.org/drop/drop.txt",
        // Spamhaus EDROP - extended DROP list
        "https://www.spamhaus.org/drop/edrop.txt",
        // Firehol Level 1 - high confidence bad IPs
        "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
        // Binary Defense - active attackers
        "https://www.binarydefense.com/banlist.txt",
    ];
}

/// <summary>
/// Configuration for the web monitoring dashboard.
/// </summary>
public sealed class WebMonitorOptions
{
    /// <summary>
    /// Whether the web monitor is enabled.
    /// </summary>
    public bool Enabled { get; set; } = true;

    /// <summary>
    /// HTTP port for the web monitoring dashboard.
    /// </summary>
    public int Port { get; set; } = 1337;
}

/// <summary>
/// Logging configuration options.
/// </summary>
public sealed class LoggingOptions
{
    /// <summary>
    /// Directory where log files are stored.
    /// </summary>
    public string LogDirectory { get; set; } = "logs";

    /// <summary>
    /// Maximum number of days to retain log files.
    /// </summary>
    public int RetentionDays { get; set; } = 15;

    /// <summary>
    /// Number of days after which to roll to a new log file.
    /// </summary>
    public int RollingIntervalDays { get; set; } = 2;

    /// <summary>
    /// Minimum log level (Verbose, Debug, Information, Warning, Error, Fatal).
    /// </summary>
    public string MinimumLevel { get; set; } = "Information";
}
