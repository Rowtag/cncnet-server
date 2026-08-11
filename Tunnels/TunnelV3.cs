using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CnCNetServer.Configuration;
using CnCNetServer.Models;
using CnCNetServer.Security;
using Serilog;

namespace CnCNetServer.Tunnels;

/// <summary>
/// V3 Tunnel Server - Modern UDP-based packet relay for CnCNet games.
///
/// Protocol Format (V3):
/// [SenderId: 4 bytes][ReceiverId: 4 bytes][Payload: N bytes]
///
/// Packet Types:
/// - Ping Request:  SenderId=0, ReceiverId=0, Size=50 bytes -> Reply with 12 bytes
/// - Registration:  SenderId!=0, ReceiverId=0, Size=8 bytes -> Store mapping
/// - Game Data:     SenderId!=0, ReceiverId!=0, Size>8 bytes -> Forward to receiver
/// - Command:       SenderId=0, ReceiverId=MaxValue -> Execute maintenance command
/// </summary>
public sealed class TunnelV3 : IDisposable
{
    // Protocol constants
    private const int ProtocolVersion = 3;

    /// <summary>
    /// The version a matchmaking server announces itself as in the master list.
    /// </summary>
    /// <remarks>
    /// A discovery label, not a wire protocol version - a matchmaking server speaks the same V3
    /// protocol. It lets clients tell the two roles apart from the master list, and makes clients
    /// that predate matchmaking skip it: they accept only versions 2 and 3, so the entry never
    /// enters their tunnel list and cannot be picked to host a game it would refuse to carry.
    /// </remarks>
    private const int MatchmakingAnnounceVersion = 4;
    private const int MinPacketSize = 8;          // Minimum valid packet: senderId + receiverId
    private const int PingPacketSize = 50;        // Expected size for ping requests
    private const int PingResponseSize = 12;      // Size of ping response
    private const int CommandPacketMinSize = 29;  // 8 (ids) + 1 (command) + 20 (SHA1 hash)

    // Rate limiting constants
    private const int CommandRateLimitSeconds = 60;

    // Windows-specific IO control code to suppress ICMP port unreachable errors
    private const int SioUdpConnReset = unchecked((int)0x9800000C);

    private readonly ILogger _logger;
    private readonly ServiceOptions _options;
    private readonly IpSecurityManager _securityManager;
    private readonly HttpClient _httpClient;

    // Core state
    private readonly Socket _socket;
    private readonly ConcurrentDictionary<uint, TunnelClient> _mappings;
    private readonly Timer _heartbeatTimer;
    private readonly byte[]? _maintenancePasswordHash;

    // Thread synchronization
    private readonly Lock _mappingsLock = new();
    private readonly CancellationTokenSource _cts = new();

    // Role. A matchmaking server relays only the client-to-client negotiation exchange, with its
    // own capacity, timeout and per-IP limits; see MatchmakingOptions.
    private readonly bool _matchmakingMode;
    private readonly int _maxClients;
    private readonly int _clientTimeout;
    private readonly int _maxRelayPacketBytes;
    private int _relayPacketCopies;

    // Mirrors _mappings.Count, maintained under _mappingsLock. ConcurrentDictionary.Count acquires
    // every internal lock, and the capacity check reads it for each packet from an unknown sender.
    private int _mappingCount;

    // Statistics
    private volatile bool _maintenanceMode;
    private long _lastCommandTicks;
    private long _packetsRelayed;
    private long _bytesRelayed;

    /// <summary>
    /// Whether this server is running in the matchmaking role rather than as a game relay.
    /// </summary>
    public bool IsMatchmakingServer => _matchmakingMode;

    /// <summary>
    /// The client limit actually in force, which depends on the server's role.
    /// </summary>
    public int MaxClients => _maxClients;

    /// <summary>
    /// How many copies of each relayed V3 packet are sent right now. This instance owns the value;
    /// <see cref="TunnelV3Options.RelayPacketCopies"/> is only the configured starting point.
    /// </summary>
    public int RelayPacketCopies => Volatile.Read(ref _relayPacketCopies);

    /// <summary>
    /// The per-IP session limit actually in force, which depends on the server's role. Unlike the
    /// other limits this is read from the options on every new session rather than captured at
    /// startup, because the web dashboard edits it live.
    /// </summary>
    private int IpLimit => _matchmakingMode ? _options.TunnelV3.Matchmaking.IpLimit : _options.TunnelV3.IpLimit;

    /// <summary>
    /// Gets whether maintenance mode is currently enabled.
    /// </summary>
    public bool IsMaintenanceMode => _maintenanceMode;

    /// <summary>
    /// Toggles maintenance mode on/off.
    /// </summary>
    public void ToggleMaintenanceMode()
    {
        _maintenanceMode = !_maintenanceMode;
        _logger.Warning("V3 Maintenance mode {Status}", _maintenanceMode ? "ENABLED" : "DISABLED");
    }

    /// <summary>
    /// Updates packet redundancy without restarting the tunnel.
    /// </summary>
    public int SetRelayPacketCopies(int copies)
    {
        // Deliberately not written back to the shared options: those describe how the process was
        // configured, and a second listener reading them must not silently inherit an edit made
        // to this one.
        var clamped = Math.Clamp(copies, 1, 3);
        var previous = Interlocked.Exchange(ref _relayPacketCopies, clamped);

        if (previous != clamped)
        {
            if (clamped > 1)
            {
                _logger.Warning(
                    "V3 packet duplication changed: every relayed packet is now sent {Copies} times.",
                    clamped);
            }
            else
            {
                _logger.Information("V3 packet duplication disabled.");
            }
        }

        return clamped;
    }

    /// <summary>
    /// Gets the number of currently connected clients.
    /// </summary>
    public int ConnectedClients
    {
        get
        {
            lock (_mappingsLock)
            {
                return _mappingCount;
            }
        }
    }

    /// <summary>
    /// Gets the number of unique IP addresses connected.
    /// </summary>
    /// <remarks>
    /// Counts numeric addresses rather than <see cref="IPAddress"/> instances to avoid building an
    /// address object per client while holding the lock the receive loop needs. Runs on every
    /// dashboard poll.
    /// </remarks>
    public int UniqueIpCount
    {
        get
        {
            var addresses = new HashSet<uint>();

            lock (_mappingsLock)
            {
                foreach (var client in _mappings.Values)
                {
                    if (client.HasRemote)
                        addresses.Add(client.RemoteAddress);
                }
            }

            return addresses.Count;
        }
    }

    /// <summary>
    /// Gets connected unique IPs grouped by ISO country code.
    /// Runs only on the status poll over the client set already held; the raw
    /// IP is used only for the look-up and never stored or returned.
    /// </summary>
    public Dictionary<string, int> GetCountryCounts(GeoResolver geo)
    {
        var counts = new Dictionary<string, int>();
        if (geo is null || !geo.Available)
        {
            return counts;
        }

        List<IPAddress> addresses;
        lock (_mappingsLock)
        {
            addresses = _mappings.Values
                .Where(c => c.RemoteEndPoint != null)
                .Select(c => c.RemoteEndPoint!.Address)
                .Distinct()
                .ToList();
        }

        foreach (var addr in addresses)
        {
            var cc = geo.Resolve(addr);
            counts[cc] = counts.TryGetValue(cc, out var n) ? n + 1 : 1;
        }

        return counts;
    }

    /// <summary>
    /// Gets the total packets relayed since startup.
    /// </summary>
    public long PacketsRelayed => Interlocked.Read(ref _packetsRelayed);

    /// <summary>
    /// Gets the total bytes relayed since startup.
    /// </summary>
    public long BytesRelayed => Interlocked.Read(ref _bytesRelayed);

    public TunnelV3(
        ServiceOptions options,
        IpSecurityManager securityManager,
        ILogger logger,
        HttpClient httpClient)
    {
        _options = options;
        _securityManager = securityManager;
        _logger = logger.ForContext<TunnelV3>();
        _httpClient = httpClient;

        // The role is fixed at startup: switching it at runtime would strand every client whose
        // session was admitted under the other role's limits.
        _matchmakingMode = options.TunnelV3.Matchmaking.Enabled;
        _maxClients = _matchmakingMode ? options.TunnelV3.Matchmaking.MaxClients : options.Server.MaxClients;
        _clientTimeout = _matchmakingMode ? options.TunnelV3.Matchmaking.ClientTimeout : options.Server.ClientTimeout;
        _maxRelayPacketBytes = options.TunnelV3.Matchmaking.MaxRelayPacketBytes;
        _relayPacketCopies = Math.Clamp(options.TunnelV3.RelayPacketCopies, 1, 3);

        // Initialize client mappings dictionary
        _mappings = new ConcurrentDictionary<uint, TunnelClient>();

        // Pre-compute maintenance password hash if configured
        if (!string.IsNullOrEmpty(_options.Maintenance.Password))
        {
            _maintenancePasswordHash = SHA256.HashData(
                Encoding.UTF8.GetBytes(_options.Maintenance.Password));
        }

        // Create UDP socket with dual-mode disabled (IPv4 only for game compatibility)
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Any, _options.TunnelV3.Port));

        // Suppress ICMP port unreachable errors on Windows
        // This prevents the socket from being closed when sending to unreachable endpoints
        TrySuppressIcmpErrors();

        // Setup heartbeat timer for master server announcements and cleanup
        var heartbeatInterval = TimeSpan.FromSeconds(_options.MasterServer.AnnounceIntervalSeconds);
        _heartbeatTimer = new Timer(OnHeartbeat, null, heartbeatInterval, heartbeatInterval);

        _lastCommandTicks = DateTime.UtcNow.Ticks;
    }

    /// <summary>
    /// Starts the tunnel server and begins receiving packets.
    /// This method blocks until the server is stopped.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token);

        // Send initial heartbeat to register with master server
        await SendHeartbeatAsync();

        _logger.Information(
            "V3 Tunnel started on UDP port {Port} in {Role} mode (max {MaxClients} clients, {Timeout}s timeout, {IpLimit} per IP)",
            _options.TunnelV3.Port,
            _matchmakingMode ? "matchmaking" : "relay",
            _maxClients,
            _clientTimeout,
            IpLimit);

        var relayPacketCopies = RelayPacketCopies;
        if (relayPacketCopies > 1)
        {
            _logger.Warning(
                "Packet duplication is on: every relayed packet is sent {Copies} times. This multiplies outbound " +
                "game bandwidth and delivers duplicate datagrams to clients.",
                relayPacketCopies);
        }

        if (_matchmakingMode)
        {
            if (_options.MasterServer.Enabled)
            {
                _logger.Information(
                    "Announcing to the master list as version {Version}, so clients can discover this as a " +
                    "matchmaking server and older clients skip it.",
                    MatchmakingAnnounceVersion);
            }
            else
            {
                _logger.Warning(
                    "Master server announcements are disabled, so clients cannot discover this matchmaking " +
                    "server. Enable them unless this server is being reached some other way.");
            }
        }

        // Main receive loop. The SocketAddress overload fills a buffer we own and reuse, where the
        // EndPoint one would build a fresh IPEndPoint per datagram, so a steady packet rate here
        // allocates nothing.
        var buffer = GC.AllocateArray<byte>(2048, pinned: true);
        var receivedAddress = new SocketAddress(AddressFamily.InterNetwork);

        while (!linkedCts.Token.IsCancellationRequested)
        {
            try
            {
                var receivedBytes = await _socket.ReceiveFromAsync(
                    buffer.AsMemory(),
                    SocketFlags.None,
                    receivedAddress,
                    linkedCts.Token);

                if (receivedBytes >= MinPacketSize && TryReadIPv4(receivedAddress, out var address, out var port))
                    ProcessPacket(buffer.AsSpan(0, receivedBytes), receivedAddress, address, port);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                // ICMP port unreachable - ignore and continue
                continue;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "Error receiving packet");
            }
        }

        _logger.Information("V3 Tunnel stopped");
    }

    /// <summary>
    /// Reads the IPv4 address and port out of a raw <see cref="SocketAddress"/>.
    /// </summary>
    /// <remarks>
    /// The layout is fixed by the sockets API: bytes 2-3 are the port in network order and bytes
    /// 4-7 the address. Reading them directly is what lets the whole receive path work in numbers
    /// instead of allocating an <see cref="IPEndPoint"/> per packet.
    /// </remarks>
    private static bool TryReadIPv4(SocketAddress socketAddress, out uint address, out int port)
    {
        address = 0;
        port = 0;

        if (socketAddress.Family != AddressFamily.InterNetwork || socketAddress.Size < 8)
            return false;

        var buffer = socketAddress.Buffer.Span;
        port = (buffer[2] << 8) | buffer[3];
        address = IpRangeSet.FromBytes(buffer.Slice(4, 4));
        return true;
    }

    /// <summary>
    /// Processes a received UDP packet.
    /// </summary>
    private void ProcessPacket(ReadOnlySpan<byte> buffer, SocketAddress socketAddress, uint address, int port)
    {
        // Parse sender and receiver IDs from the packet header
        var senderId = BitConverter.ToUInt32(buffer);
        var receiverId = BitConverter.ToUInt32(buffer.Slice(4));

        // Validate remote endpoint - reject loopback, broadcast, and invalid addresses
        if (!IsValidRemoteEndPoint(address, port))
            return;

        // Validate packet format against known V3 protocol patterns
        if (!TunnelV3PacketValidation.IsValidPacket(buffer, buffer.Length, senderId, receiverId))
            return;

        // Check DDoS protection - blocked IPs
        if (_options.TunnelV3.DDoSProtectionEnabled &&
            !_securityManager.IsConnectionAllowed(address))
            return;

        // Handle command packets (senderId=0, receiverId=MaxValue)
        if (senderId == 0 && receiverId == uint.MaxValue && buffer.Length >= CommandPacketMinSize)
        {
            ProcessCommand(buffer);
            return;
        }

        // Handle ping packets (senderId=0, receiverId=0, size=50)
        if (senderId == 0 && receiverId == 0)
        {
            if (buffer.Length == PingPacketSize)
            {
                ProcessPing(buffer, socketAddress, address);
            }
            return;
        }

        // Reject packets where sender equals receiver (invalid)
        if (senderId == receiverId)
            return;

        // A matchmaking server exists only to carry the tunnel list exchange between two clients.
        // Anything else addressed to a peer - game data above all - is dropped here, before it can
        // create a session, so a matchmaking server can never be pressed into relaying a game.
        if (_matchmakingMode && receiverId != 0 &&
            !TunnelV3PacketValidation.IsNegotiationPacket(buffer, _maxRelayPacketBytes))
            return;

        // Handle registration and relay packets
        ProcessDataPacket(buffer, senderId, receiverId, socketAddress, address, port);
    }

    /// <summary>
    /// Processes a ping request and sends a response.
    /// </summary>
    private void ProcessPing(ReadOnlySpan<byte> buffer, SocketAddress socketAddress, uint address)
    {
        // Check rate limits for pings (DDoS protection)
        if (_options.TunnelV3.DDoSProtectionEnabled &&
            !_securityManager.IsPingAllowed(
                address,
                _options.Security.MaxPingsPerIp,
                _options.Security.MaxPingsGlobal))
        {
            return;
        }

        // Send back the first 12 bytes as ping response
        // Uses stackalloc to avoid heap allocation
        Span<byte> response = stackalloc byte[PingResponseSize];
        buffer.Slice(0, PingResponseSize).CopyTo(response);

        try
        {
            // Replies straight to the address we received on, so no endpoint is materialised.
            _socket.SendTo(response, SocketFlags.None, socketAddress);
        }
        catch (SocketException)
        {
            // Ignore send failures (client may have disconnected)
        }
    }

    /// <summary>
    /// Processes a data packet (registration or relay).
    /// </summary>
    /// <remarks>
    /// The lock covers only the session bookkeeping. The forwarding send is left outside it because
    /// the heartbeat's expiry sweep takes the same lock and walks every mapping, and at matchmaking
    /// client counts the receive loop should not queue behind that while holding a blocking write.
    /// Capturing the receiver's SocketAddress is what makes that safe: it is only ever replaced with
    /// a new instance, never mutated, so the reference stays a valid snapshot once the lock is out.
    /// </remarks>
    private void ProcessDataPacket(
        ReadOnlySpan<byte> buffer,
        uint senderId,
        uint receiverId,
        SocketAddress socketAddress,
        uint address,
        int port)
    {
        var ddosEnabled = _options.TunnelV3.DDoSProtectionEnabled;
        SocketAddress? forwardTo = null;

        lock (_mappingsLock)
        {
            // Try to find existing sender mapping
            if (_mappings.TryGetValue(senderId, out var sender))
            {
                // Verify the sender's endpoint matches. Compared numerically so the common case -
                // a packet from the endpoint we already know - costs two integer comparisons.
                if (sender.HasRemote && !sender.Matches(address, port))
                {
                    // Endpoint mismatch - only allow takeover if timed out and not in maintenance
                    if (sender.IsTimedOut && !_maintenanceMode)
                    {
                        // Only the port changed (a NAT rebind of the same client) - the IP is
                        // already tracked, so re-tracking it would consume a second slot and could
                        // reject a client that is merely reconnecting.
                        var addressChanged = address != sender.RemoteAddress;

                        if (ddosEnabled && addressChanged)
                        {
                            // Claim the new IP's slot before releasing the old one. Releasing first
                            // would leave the session untracked if the new IP turns out to be over
                            // its limit, and the mapping's eventual expiry would then release a
                            // slot it no longer holds.
                            if (!_securityManager.TrackConnection(address, IpLimit))
                                return;

                            _securityManager.ReleaseConnection(sender.RemoteAddress);
                        }

                        sender.SetRemote(address, port, socketAddress);
                    }
                    else
                    {
                        return; // Reject - different endpoint for active session
                    }
                }

                sender.UpdateLastActivity();
            }
            else
            {
                // New client registration. The count is tracked alongside the dictionary because
                // ConcurrentDictionary.Count takes all of its internal locks, and this runs for
                // every packet that arrives from an unknown sender - i.e. for every packet of a
                // flood of forged sender IDs.
                if (_mappingCount >= _maxClients || _maintenanceMode)
                    return;

                // Check IP limit (DDoS protection)
                if (ddosEnabled && !_securityManager.TrackConnection(address, IpLimit))
                    return;

                sender = new TunnelClient(_clientTimeout);
                sender.SetRemote(address, port, socketAddress);

                _mappings[senderId] = sender;
                _mappingCount++;
            }

            // If this is a relay packet (has receiver), note where it goes
            if (receiverId != 0 && _mappings.TryGetValue(receiverId, out var receiver))
            {
                if (receiver.HasRemote && !receiver.Matches(address, port))
                    forwardTo = receiver.RemoteSocketAddress;
            }
        }

        if (forwardTo == null)
            return;

        // Send the packet more than once when configured to, trading upstream bandwidth for
        // resilience to loss on the server-to-receiver leg. See RelayPacketCopies for what this
        // does and does not protect against.
        var relayPacketCopies = RelayPacketCopies;
        for (var copy = 0; copy < relayPacketCopies; copy++)
        {
            try
            {
                _socket.SendTo(buffer, SocketFlags.None, forwardTo);
                Interlocked.Increment(ref _packetsRelayed);
                Interlocked.Add(ref _bytesRelayed, buffer.Length);
            }
            catch (SocketException)
            {
                // Ignore send failures
                break;
            }
        }
    }

    /// <summary>
    /// Processes a maintenance command packet.
    /// </summary>
    private void ProcessCommand(ReadOnlySpan<byte> buffer)
    {
        if (_maintenancePasswordHash == null)
            return;

        // Rate limit command execution
        var now = DateTime.UtcNow.Ticks;
        var lastCommand = Interlocked.Read(ref _lastCommandTicks);
        if (TimeSpan.FromTicks(now - lastCommand).TotalSeconds < CommandRateLimitSeconds)
            return;

        // Extract command byte and password hash
        var command = buffer[8];
        var providedHash = buffer.Slice(9, 32); // SHA256 is 32 bytes

        // Verify password hash using constant-time comparison
        if (!CryptographicOperations.FixedTimeEquals(providedHash, _maintenancePasswordHash))
            return;

        Interlocked.Exchange(ref _lastCommandTicks, now);

        // Execute command
        switch (command)
        {
            case 0: // Toggle maintenance mode
                _maintenanceMode = !_maintenanceMode;
                _logger.Warning("Maintenance mode {Status}", _maintenanceMode ? "ENABLED" : "DISABLED");
                break;
        }
    }

    /// <summary>
    /// Validates that a remote endpoint is valid for tunneling. Rejects the unspecified, loopback
    /// and broadcast addresses, compared numerically so no address object is built per packet.
    /// </summary>
    private static bool IsValidRemoteEndPoint(uint address, int port)
    {
        const uint Any = 0x00000000;             // 0.0.0.0
        const uint Loopback = 0x7F000001;        // 127.0.0.1
        const uint Broadcast = 0xFFFFFFFF;       // 255.255.255.255

        return port != 0 && address != Any && address != Loopback && address != Broadcast;
    }

    /// <summary>
    /// Heartbeat timer callback - cleans up expired clients and sends master server announcement.
    /// </summary>
    private async void OnHeartbeat(object? state)
    {
        CleanupExpiredClients();
        _securityManager.ResetRateLimits();
        await SendHeartbeatAsync();
    }

    /// <summary>
    /// Removes timed-out clients from the mappings.
    /// </summary>
    private void CleanupExpiredClients()
    {
        // Created only when something has actually expired - most sweeps find nothing, and this
        // one runs on a timer for the lifetime of the process.
        List<uint>? expiredIds = null;
        var ddosEnabled = _options.TunnelV3.DDoSProtectionEnabled;

        lock (_mappingsLock)
        {
            foreach (var (id, client) in _mappings)
            {
                if (client.IsTimedOut)
                {
                    (expiredIds ??= []).Add(id);
                    // Release connection tracking
                    if (ddosEnabled && client.HasRemote)
                    {
                        _securityManager.ReleaseConnection(client.RemoteAddress);
                    }
                }
            }

            foreach (var id in expiredIds ?? [])
            {
                if (_mappings.TryRemove(id, out _))
                    _mappingCount--;
            }
        }

        if (expiredIds is { Count: > 0 })
        {
            _logger.Debug("Cleaned up {Count} expired V3 clients", expiredIds.Count);
        }
    }

    /// <summary>
    /// Sends a heartbeat announcement to the master server.
    /// </summary>
    private async Task SendHeartbeatAsync()
    {
        if (!_options.MasterServer.Enabled)
            return;

        try
        {
            var clientCount = ConnectedClients;
            var url = BuildMasterServerUrl(clientCount);

            var response = await _httpClient.GetAsync(url, _cts.Token);
            response.EnsureSuccessStatusCode();

            _logger.Debug("V3 master server heartbeat sent: {Clients} clients", clientCount);
        }
        catch (Exception ex)
        {
            _logger.Warning("V3 master server heartbeat failed: {Error}", ex.Message);
        }
    }

    /// <summary>
    /// Builds the master server announcement URL with current status.
    /// </summary>
    private string BuildMasterServerUrl(int clientCount)
    {
        var parameters = new Dictionary<string, string>
        {
            ["version"] = (_matchmakingMode ? MatchmakingAnnounceVersion : ProtocolVersion).ToString(),
            ["name"] = _options.Server.Name,
            ["port"] = _options.TunnelV3.Port.ToString(),
            ["clients"] = clientCount.ToString(),

            // Clients use the announced occupancy to avoid negotiating onto a server that is about
            // to start rejecting registrations, so this has to be the limit actually in force.
            ["maxclients"] = _maxClients.ToString(),
            ["maintenance"] = _maintenanceMode ? "1" : "0"
        };

        if (!string.IsNullOrEmpty(_options.MasterServer.Password))
        {
            parameters["masterpw"] = _options.MasterServer.Password;
        }

        var queryString = string.Join("&",
            parameters.Select(p => $"{p.Key}={Uri.EscapeDataString(p.Value)}"));

        return $"{_options.MasterServer.Url}?{queryString}";
    }

    /// <summary>
    /// Suppresses ICMP port unreachable errors on Windows.
    /// </summary>
    private void TrySuppressIcmpErrors()
    {
        try
        {
            // This IOControl call is Windows-specific and will fail on Linux/macOS
            _socket.IOControl(SioUdpConnReset, [0, 0, 0, 0], null);
        }
        catch
        {
            // Expected to fail on non-Windows platforms - ignore
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _heartbeatTimer.Dispose();
        _socket.Dispose();
        _cts.Dispose();
    }
}
