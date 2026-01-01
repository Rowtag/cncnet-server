using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using CnCNetServer.Configuration;
using CnCNetServer.Diagnostics;
using CnCNetServer.Logging;
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

    // Statistics
    private volatile bool _maintenanceMode;
    private long _lastCommandTicks;
    private long _packetsRelayed;
    private long _bytesRelayed;

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
    /// Gets the number of currently connected clients.
    /// </summary>
    public int ConnectedClients
    {
        get
        {
            lock (_mappingsLock)
            {
                return _mappings.Count;
            }
        }
    }

    /// <summary>
    /// Gets the number of established clients (sessions active for more than 2 minutes).
    /// These are likely real game sessions, not just slot reservations.
    /// </summary>
    public int EstablishedClients
    {
        get
        {
            lock (_mappingsLock)
            {
                return _mappings.Values
                    .Count(c => c.RemoteEndPoint != null && c.SessionDuration.TotalMinutes >= 2);
            }
        }
    }

    /// <summary>
    /// Gets the number of unique IP addresses connected.
    /// </summary>
    public int UniqueIpCount
    {
        get
        {
            lock (_mappingsLock)
            {
                return _mappings.Values
                    .Where(c => c.RemoteEndPoint != null)
                    .Select(c => c.RemoteEndPoint!.Address)
                    .Distinct()
                    .Count();
            }
        }
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

        // Initialize client mappings dictionary
        _mappings = new ConcurrentDictionary<uint, TunnelClient>();

        // Pre-compute maintenance password hash if configured
        if (!string.IsNullOrEmpty(_options.Maintenance.Password))
        {
            _maintenancePasswordHash = SHA256.HashData(
                Encoding.UTF8.GetBytes(_options.Maintenance.Password));
        }

        // Create UDP socket with IPv4 only (games don't support IPv6)
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

        _logger.Information("V3 Tunnel started on UDP port {Port}", _options.TunnelV3.Port);

        // Main receive loop using modern Socket.ReceiveFromAsync
        var buffer = GC.AllocateArray<byte>(2048, pinned: true);
        var remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

        while (!linkedCts.Token.IsCancellationRequested)
        {
            try
            {
                var result = await _socket.ReceiveFromAsync(
                    buffer.AsMemory(),
                    SocketFlags.None,
                    remoteEndPoint,
                    linkedCts.Token);

                if (result.ReceivedBytes >= MinPacketSize)
                {
                    ProcessPacket(
                        buffer.AsSpan(0, result.ReceivedBytes),
                        (IPEndPoint)result.RemoteEndPoint);
                }
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
    /// Processes a received UDP packet.
    /// </summary>
    private void ProcessPacket(ReadOnlySpan<byte> buffer, IPEndPoint remoteEndPoint)
    {
        // Parse sender and receiver IDs from the packet header
        var senderId = BitConverter.ToUInt32(buffer);
        var receiverId = BitConverter.ToUInt32(buffer.Slice(4));

        // Validate remote endpoint - reject loopback, broadcast, and invalid addresses
        if (!IsValidRemoteEndPoint(remoteEndPoint))
        {
            ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.InvalidPacket,
                $"Invalid endpoint rejected (loopback/broadcast/invalid)", TunnelSource.V3);
            return;
        }

        // Validate packet format against known V3 protocol patterns
        if (!TunnelV3PacketValidation.IsValidPacket(buffer, buffer.Length, senderId, receiverId))
        {
            ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.InvalidPacket,
                $"Packet validation failed: size={buffer.Length}, senderId={senderId}, receiverId={receiverId}", TunnelSource.V3);
            return;
        }

        // Check DDoS protection - blocked IPs
        if (_options.TunnelV3.DDoSProtectionEnabled &&
            !_securityManager.IsConnectionAllowed(remoteEndPoint.Address))
        {
            ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.ConnectionRejected,
                "Blocked by security manager (blacklist or rate limit)", TunnelSource.V3);
            return;
        }

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
                ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.V3PingReceived,
                    $"Ping request received ({buffer.Length} bytes)", TunnelSource.V3);
                ProcessPing(buffer, remoteEndPoint);
            }
            return;
        }

        // Reject packets where sender equals receiver (invalid)
        if (senderId == receiverId)
        {
            ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.InvalidPacket,
                $"Sender equals receiver rejected: id={senderId}", TunnelSource.V3);
            return;
        }

        // Handle registration and relay packets
        ProcessDataPacket(buffer, senderId, receiverId, remoteEndPoint);
    }

    /// <summary>
    /// Processes a ping request and sends a response.
    /// </summary>
    private void ProcessPing(ReadOnlySpan<byte> buffer, IPEndPoint remoteEndPoint)
    {
        // Check rate limits for pings (DDoS protection)
        if (_options.TunnelV3.DDoSProtectionEnabled &&
            !_securityManager.IsPingAllowed(
                remoteEndPoint.Address,
                _options.Security.MaxPingsPerIp,
                _options.Security.MaxPingsGlobal))
        {
            ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.BlockedByRateLimit,
                "Ping blocked by rate limit", TunnelSource.V3);
            return;
        }

        // Send back the first 12 bytes as ping response
        // Uses stackalloc to avoid heap allocation
        Span<byte> response = stackalloc byte[PingResponseSize];
        buffer.Slice(0, PingResponseSize).CopyTo(response);

        try
        {
            _socket.SendTo(response, SocketFlags.None, remoteEndPoint);
            ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.V3PingResponse,
                $"Ping response sent ({PingResponseSize} bytes)", TunnelSource.V3);
        }
        catch (SocketException ex)
        {
            ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.SendFailed,
                $"Ping response failed: {ex.SocketErrorCode}", TunnelSource.V3);
        }
    }

    /// <summary>
    /// Processes a data packet (registration or relay).
    /// PERFORMANCE: SendTo is performed OUTSIDE the lock to prevent blocking other packets.
    /// </summary>
    private void ProcessDataPacket(
        ReadOnlySpan<byte> buffer,
        uint senderId,
        uint receiverId,
        IPEndPoint remoteEndPoint)
    {
        var ddosEnabled = _options.TunnelV3.DDoSProtectionEnabled;
        IPEndPoint? targetEndPoint = null;
        bool shouldRelay = false;
        int bufferLength = buffer.Length;

        lock (_mappingsLock)
        {
            // Try to find existing sender mapping
            if (_mappings.TryGetValue(senderId, out var sender))
            {
                // Verify the sender's IP address matches (port changes allowed for NAT rebinding)
                bool ipMatches = sender.RemoteEndPoint == null ||
                    remoteEndPoint.Address.Equals(sender.RemoteEndPoint.Address);

                if (!ipMatches)
                {
                    // Different IP - only allow takeover if timed out and not in maintenance
                    if (sender.IsTimedOut && !_maintenanceMode)
                    {
                        // Release old connection tracking
                        if (ddosEnabled && sender.RemoteEndPoint != null)
                            _securityManager.ReleaseConnection(sender.RemoteEndPoint.Address);

                        // Check if new connection is allowed (IP limit)
                        if (ddosEnabled &&
                            !_securityManager.TrackConnection(remoteEndPoint.Address, _options.TunnelV3.IpLimit))
                            return;

                        sender.RemoteEndPoint = new IPEndPoint(remoteEndPoint.Address, remoteEndPoint.Port);
                    }
                    else
                    {
                        return; // Reject - different IP for active session
                    }
                }
                else if (sender.RemoteEndPoint != null && sender.RemoteEndPoint.Port != remoteEndPoint.Port)
                {
                    // Same IP but different port (NAT rebinding) - update the port
                    sender.RemoteEndPoint = new IPEndPoint(remoteEndPoint.Address, remoteEndPoint.Port);
                }

                sender.UpdateLastActivity();
            }
            else
            {
                // New client registration
                if (_mappings.Count >= _options.Server.MaxClients || _maintenanceMode)
                {
                    ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.ConnectionRejected,
                        _maintenanceMode ? "Rejected: maintenance mode" : "Rejected: server full", TunnelSource.V3);
                    return;
                }

                // Check IP limit (DDoS protection)
                if (ddosEnabled &&
                    !_securityManager.TrackConnection(remoteEndPoint.Address, _options.TunnelV3.IpLimit))
                {
                    ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.BlockedByIpLimit,
                        $"Rejected: IP limit exceeded (limit: {_options.TunnelV3.IpLimit})", TunnelSource.V3);
                    return;
                }

                sender = new TunnelClient(
                    new IPEndPoint(remoteEndPoint.Address, remoteEndPoint.Port),
                    _options.Server.ClientTimeout);

                _mappings[senderId] = sender;

                ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.V3Registration,
                    $"New client registered with ID {senderId}", TunnelSource.V3);
            }

            // If this is a relay packet (has receiver), prepare for forwarding OUTSIDE lock
            if (receiverId != 0 &&
                _mappings.TryGetValue(receiverId, out var receiver) &&
                receiver.RemoteEndPoint != null &&
                !receiver.RemoteEndPoint.Equals(sender.RemoteEndPoint))
            {
                // Update receiver's activity - they're still part of an active game
                receiver.UpdateLastActivity();

                // Copy endpoint for use outside lock
                targetEndPoint = receiver.RemoteEndPoint;
                shouldRelay = true;
            }
        }

        // PERFORMANCE: SendTo is done OUTSIDE the lock to prevent blocking other packets
        if (shouldRelay && targetEndPoint != null)
        {
            try
            {
                _socket.SendTo(buffer, SocketFlags.None, targetEndPoint);
                Interlocked.Increment(ref _packetsRelayed);
                Interlocked.Add(ref _bytesRelayed, bufferLength);

                ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.V3PacketRelayed,
                    $"Packet relayed to {receiverId} ({bufferLength} bytes)", TunnelSource.V3);
            }
            catch (SocketException ex)
            {
                ConnectionTracer.Instance.LogEvent(remoteEndPoint, TraceEventType.SendFailed,
                    $"Relay to {receiverId} failed: {ex.SocketErrorCode}", TunnelSource.V3);
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
    /// Validates that a remote endpoint is valid for tunneling.
    /// </summary>
    private static bool IsValidRemoteEndPoint(IPEndPoint endPoint)
    {
        return endPoint.Port != 0 &&
               !IPAddress.IsLoopback(endPoint.Address) &&
               !endPoint.Address.Equals(IPAddress.Any) &&
               !endPoint.Address.Equals(IPAddress.Broadcast);
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
        var expiredIds = new List<uint>();
        var ddosEnabled = _options.TunnelV3.DDoSProtectionEnabled;
        var timeout = _options.Server.ClientTimeout;

        lock (_mappingsLock)
        {

            foreach (var (id, client) in _mappings)
            {
                if (client.IsTimedOut)
                {
                    expiredIds.Add(id);

                    // Log completed session if client had an endpoint
                    if (client.RemoteEndPoint != null)
                    {
                        ConnectionTracer.Instance.LogEvent(client.RemoteEndPoint, TraceEventType.ConnectionTimeout,
                            $"Session timed out after {client.SessionDuration.TotalSeconds:F0}s, TimeSinceLastActivity={client.TimeSinceLastActivity.TotalSeconds:F1}s, Timeout={timeout}s", TunnelSource.V3);

                        SessionLog.V3.LogSession(
                            client.RemoteEndPoint.Address.ToString(),
                            client.SessionDuration);

                        // Release connection tracking
                        if (ddosEnabled)
                        {
                            _securityManager.ReleaseConnection(client.RemoteEndPoint.Address);
                        }
                    }
                }
            }

            foreach (var id in expiredIds)
            {
                _mappings.TryRemove(id, out _);
            }
        }

        if (expiredIds.Count > 0)
        {
            _logger.Debug("Cleaned up {Count} expired V3 clients", expiredIds.Count);
        }
    }

    /// <summary>
    /// Sends a heartbeat announcement to the master server.
    /// Skips heartbeat during maintenance mode so the server is removed from the list.
    /// </summary>
    private async Task SendHeartbeatAsync()
    {
        if (!_options.MasterServer.Enabled)
            return;

        // Skip heartbeat during maintenance - server will be removed from master list
        if (_maintenanceMode)
        {
            _logger.Debug("V3 master server heartbeat skipped (maintenance mode)");
            return;
        }

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
    /// Note: In maintenance mode, we skip the heartbeat entirely to avoid
    /// sending unsupported parameters to the master server.
    /// </summary>
    private string BuildMasterServerUrl(int clientCount)
    {
        var parameters = new Dictionary<string, string>
        {
            ["version"] = ProtocolVersion.ToString(),
            ["name"] = _options.Server.Name,
            ["port"] = _options.TunnelV3.Port.ToString(),
            ["clients"] = clientCount.ToString(),
            ["maxclients"] = _options.Server.MaxClients.ToString()
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
