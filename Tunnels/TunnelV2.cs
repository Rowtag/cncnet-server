using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Security.Cryptography;
using System.Text.Json;
using CnCNetServer.Configuration;
using CnCNetServer.Models;
using CnCNetServer.Security;
using Serilog;

namespace CnCNetServer.Tunnels;

/// <summary>
/// V2 Tunnel Server - Legacy HTTP+UDP based packet relay for CnCNet games.
///
/// This tunnel uses HTTP for session allocation and UDP for packet relay.
/// Clients first request slots via HTTP, then communicate via UDP using assigned IDs.
///
/// HTTP Endpoints:
/// - GET /request?clients=N  -> Allocates N client slots (2-8), returns JSON array of IDs
/// - GET /status             -> Returns server status (slots free/in use)
///
/// UDP Protocol Format (V2):
/// [SenderId: 2 bytes (network order)][ReceiverId: 2 bytes (network order)][Payload: N bytes]
/// </summary>
public sealed class TunnelV2 : IDisposable
{
    // Protocol constants
    private const int ProtocolVersion = 2;
    private const int MinPacketSize = 4;          // Minimum valid packet: senderId + receiverId
    private const int PingPacketSize = 50;        // Expected size for ping requests
    private const int PingResponseSize = 12;      // Size of ping response
    private const int MinClientsPerRequest = 2;   // Minimum clients per game request
    private const int MaxClientsPerRequest = 8;   // Maximum clients per game request
    private const int MaxRequestsGlobal = 1000;   // Maximum concurrent HTTP requests

    // Windows-specific IO control code
    private const int SioUdpConnReset = unchecked((int)0x9800000C);

    private readonly ILogger _logger;
    private readonly ServiceOptions _options;
    private readonly IpSecurityManager _securityManager;
    private readonly HttpClient _httpClient;

    // UDP socket for packet relay
    private readonly Socket _socket;

    // HTTP listener for client allocation
    private readonly HttpListener _httpListener;

    // Client mappings (short ID -> TunnelClient)
    private readonly ConcurrentDictionary<short, TunnelClient> _mappings;

    // Request rate limiting per IP
    private readonly ConcurrentDictionary<string, int> _requestCounter;

    // Heartbeat timer
    private readonly Timer _heartbeatTimer;

    // Thread synchronization
    private readonly Lock _mappingsLock = new();
    private readonly CancellationTokenSource _cts = new();
    // Cryptographically secure random for client ID generation

    // State
    private volatile bool _maintenanceMode;
    private long _packetsRelayed;
    private long _bytesRelayed;
    private int _activeRequestCount;

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
        _logger.Warning("V2 Maintenance mode {Status}", _maintenanceMode ? "ENABLED" : "DISABLED");
    }

    /// <summary>
    /// Gets the number of allocated client slots.
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
    /// Gets the number of reserved slots (clients with assigned endpoints).
    /// </summary>
    public int ReservedSlots
    {
        get
        {
            lock (_mappingsLock)
            {
                return _mappings.Values.Count(c => c.RemoteEndPoint != null);
            }
        }
    }

    /// <summary>
    /// Gets the number of unique IP addresses.
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

    public TunnelV2(
        ServiceOptions options,
        IpSecurityManager securityManager,
        ILogger logger,
        HttpClient httpClient)
    {
        _options = options;
        _securityManager = securityManager;
        _logger = logger.ForContext<TunnelV2>();
        _httpClient = httpClient;

        _mappings = new ConcurrentDictionary<short, TunnelClient>();
        _requestCounter = new ConcurrentDictionary<string, int>();

        // Create UDP socket
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Any, _options.TunnelV2.Port));
        TrySuppressIcmpErrors();

        // Create HTTP listener
        // Note: http://+: requires admin rights or URL ACL reservation
        // Use http://localhost: for testing without admin rights
        _httpListener = new HttpListener();
        _httpListener.Prefixes.Add($"http://+:{_options.TunnelV2.Port}/");
        _httpListener.IgnoreWriteExceptions = true;

        // Setup heartbeat timer
        var heartbeatInterval = TimeSpan.FromSeconds(_options.MasterServer.AnnounceIntervalSeconds);
        _heartbeatTimer = new Timer(OnHeartbeat, null, heartbeatInterval, heartbeatInterval);
    }

    /// <summary>
    /// Starts the V2 tunnel server (HTTP and UDP listeners).
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token);

        // Try to start HTTP listener (requires admin rights or URL ACL)
        try
        {
            _httpListener.Start();
            _logger.Information("V2 Tunnel HTTP listener started on port {Port}", _options.TunnelV2.Port);
        }
        catch (HttpListenerException ex)
        {
            _logger.Warning(
                "V2 HTTP listener failed to start (requires admin rights or URL ACL): {Error}. " +
                "UDP relay will still work. Run as admin or execute: " +
                "netsh http add urlacl url=http://+:{Port}/ user=Everyone",
                ex.Message, _options.TunnelV2.Port);
        }

        // Send initial heartbeat
        await SendHeartbeatAsync();

        _logger.Information("V2 Tunnel started on port {Port} (UDP)", _options.TunnelV2.Port);

        // Run HTTP and UDP listeners concurrently
        var tasks = new List<Task> { RunUdpListenerAsync(linkedCts.Token) };

        if (_httpListener.IsListening)
        {
            tasks.Add(RunHttpListenerAsync(linkedCts.Token));
        }

        await Task.WhenAll(tasks);

        _logger.Information("V2 Tunnel stopped");
    }

    /// <summary>
    /// Runs the HTTP listener for client slot allocation.
    /// </summary>
    private async Task RunHttpListenerAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var context = await _httpListener.GetContextAsync().WaitAsync(cancellationToken);
                _ = ProcessHttpRequestAsync(context); // Fire and forget
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (HttpListenerException ex) when (ex.ErrorCode == 995) // Operation aborted
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "HTTP listener error");
            }
        }
    }

    /// <summary>
    /// Processes an incoming HTTP request.
    /// </summary>
    private async Task ProcessHttpRequestAsync(HttpListenerContext context)
    {
        var response = context.Response;
        var request = context.Request;
        response.KeepAlive = false;

        try
        {
            // Check request rate limit
            if (Interlocked.Increment(ref _activeRequestCount) > MaxRequestsGlobal)
            {
                response.StatusCode = 429; // Too Many Requests
                return;
            }

            // Check IP-based rate limit
            if (!CheckRequestLimit(request.RemoteEndPoint?.Address))
            {
                response.StatusCode = 429;
                return;
            }

            // Route request
            var path = request.Url?.AbsolutePath ?? "/";

            if (path.Equals("/request", StringComparison.OrdinalIgnoreCase))
            {
                await HandleSlotRequestAsync(request, response);
            }
            else if (path.Equals("/status", StringComparison.OrdinalIgnoreCase))
            {
                await HandleStatusRequestAsync(response);
            }
            // /maintenance/{pw} endpoint removed - use web dashboard instead
            else
            {
                response.StatusCode = 400; // Bad Request
            }
        }
        catch (Exception ex)
        {
            _logger.Warning("HTTP request error: {Error}", ex.Message);
            response.StatusCode = 500;
        }
        finally
        {
            Interlocked.Decrement(ref _activeRequestCount);
            try { response.Close(); } catch { }
        }
    }

    /// <summary>
    /// Handles a slot allocation request.
    /// </summary>
    private async Task HandleSlotRequestAsync(HttpListenerRequest request, HttpListenerResponse response)
    {
        // Check maintenance mode
        if (_maintenanceMode)
        {
            response.StatusCode = 503; // Service Unavailable
            return;
        }

        // Parse client count from query string
        var clientsParam = request.QueryString["clients"];
        if (!int.TryParse(clientsParam, out var requestedClients) ||
            requestedClients < MinClientsPerRequest ||
            requestedClients > MaxClientsPerRequest)
        {
            response.StatusCode = 400;
            return;
        }

        var allocatedIds = new List<short>(requestedClients);

        lock (_mappingsLock)
        {
            // Check if we have enough capacity
            if (_mappings.Count + requestedClients > _options.Server.MaxClients)
            {
                response.StatusCode = 503;
                return;
            }

            // Allocate client IDs
            while (allocatedIds.Count < requestedClients)
            {
                var clientId = (short)RandomNumberGenerator.GetInt32(short.MinValue, short.MaxValue);

                if (!_mappings.ContainsKey(clientId))
                {
                    var client = new TunnelClient(_options.Server.ClientTimeout);
                    _mappings[clientId] = client;
                    allocatedIds.Add(clientId);
                }
            }
        }

        // Return allocated IDs as JSON array
        var json = JsonSerializer.Serialize(allocatedIds);
        var buffer = Encoding.UTF8.GetBytes(json);

        response.ContentType = "application/json";
        response.ContentLength64 = buffer.Length;
        await response.OutputStream.WriteAsync(buffer);
    }

    /// <summary>
    /// Handles a status request.
    /// </summary>
    private async Task HandleStatusRequestAsync(HttpListenerResponse response)
    {
        int used, free;

        lock (_mappingsLock)
        {
            used = _mappings.Count;
            free = _options.Server.MaxClients - used;
        }

        var status = $"{free} slots free.\n{used} slots in use.\n";
        var buffer = Encoding.UTF8.GetBytes(status);

        response.ContentType = "text/plain";
        response.ContentLength64 = buffer.Length;
        await response.OutputStream.WriteAsync(buffer);
    }



    /// <summary>
    /// Checks if a request from an IP is within rate limits.
    /// </summary>
    private bool CheckRequestLimit(IPAddress? address)
    {
        if (address == null)
            return false;

        var count = _requestCounter.AddOrUpdate(address.ToString(), 1, (_, c) => c + 1);

        return count <= _options.TunnelV2.IpLimit;
    }

    /// <summary>
    /// Runs the UDP listener for packet relay.
    /// </summary>
    private async Task RunUdpListenerAsync(CancellationToken cancellationToken)
    {
        var buffer = GC.AllocateArray<byte>(2048, pinned: true);
        var remoteEndPoint = new IPEndPoint(IPAddress.Any, 0);

        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var result = await _socket.ReceiveFromAsync(
                    buffer.AsMemory(),
                    SocketFlags.None,
                    remoteEndPoint,
                    cancellationToken);

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
                continue;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "UDP receive error");
            }
        }
    }

    /// <summary>
    /// Processes a received UDP packet.
    /// </summary>
    private void ProcessPacket(ReadOnlySpan<byte> buffer, IPEndPoint remoteEndPoint)
    {
        // Parse IDs in network byte order (big-endian)
        var senderId = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer));
        var receiverId = IPAddress.NetworkToHostOrder(BitConverter.ToInt16(buffer.Slice(2)));

        // Validate remote endpoint
        if (!IsValidRemoteEndPoint(remoteEndPoint))
            return;

        // Reject packets where sender equals receiver
        if (senderId == receiverId && senderId != 0)
            return;

        // Handle ping packets (senderId=0, receiverId=0, size=50)
        if (senderId == 0 && receiverId == 0)
        {
            if (buffer.Length == PingPacketSize)
            {
                ProcessPing(buffer, remoteEndPoint);
            }
            return;
        }

        // Handle data relay
        ProcessDataPacket(buffer, senderId, receiverId, remoteEndPoint);
    }

    /// <summary>
    /// Processes a ping request.
    /// </summary>
    private void ProcessPing(ReadOnlySpan<byte> buffer, IPEndPoint remoteEndPoint)
    {
        if (!_securityManager.IsPingAllowed(
            remoteEndPoint.Address,
            _options.Security.MaxPingsPerIp,
            _options.Security.MaxPingsGlobal))
        {
            return;
        }

        Span<byte> response = stackalloc byte[PingResponseSize];
        buffer.Slice(0, PingResponseSize).CopyTo(response);

        try
        {
            _socket.SendTo(response, SocketFlags.None, remoteEndPoint);
        }
        catch (SocketException)
        {
            // Ignore
        }
    }

    /// <summary>
    /// Processes a data packet for relay.
    /// </summary>
    private void ProcessDataPacket(
        ReadOnlySpan<byte> buffer,
        short senderId,
        short receiverId,
        IPEndPoint remoteEndPoint)
    {
        lock (_mappingsLock)
        {
            // Look up sender in mappings
            if (!_mappings.TryGetValue(senderId, out var sender))
                return; // Unknown sender - reject

            // First packet from this sender - assign endpoint
            if (sender.RemoteEndPoint == null)
            {
                sender.RemoteEndPoint = new IPEndPoint(remoteEndPoint.Address, remoteEndPoint.Port);
            }
            // Endpoint mismatch - reject (V2 doesn't allow endpoint changes)
            else if (!remoteEndPoint.Equals(sender.RemoteEndPoint))
            {
                return;
            }

            sender.UpdateLastActivity();

            // Relay to receiver if specified and valid
            if (receiverId != 0 &&
                _mappings.TryGetValue(receiverId, out var receiver) &&
                receiver.RemoteEndPoint != null &&
                !receiver.RemoteEndPoint.Equals(sender.RemoteEndPoint))
            {
                try
                {
                    _socket.SendTo(buffer, SocketFlags.None, receiver.RemoteEndPoint);
                    Interlocked.Increment(ref _packetsRelayed);
                    Interlocked.Add(ref _bytesRelayed, buffer.Length);
                }
                catch (SocketException)
                {
                    // Ignore
                }
            }
        }
    }

    /// <summary>
    /// Validates a remote endpoint.
    /// </summary>
    private static bool IsValidRemoteEndPoint(IPEndPoint endPoint)
    {
        return endPoint.Port != 0 &&
               !endPoint.Address.Equals(IPAddress.Loopback) &&
               !endPoint.Address.Equals(IPAddress.Any) &&
               !endPoint.Address.Equals(IPAddress.Broadcast);
    }

    /// <summary>
    /// Heartbeat timer callback.
    /// </summary>
    private async void OnHeartbeat(object? state)
    {
        CleanupExpiredClients();
        ResetRequestCounter();
        _securityManager.ResetRateLimits();
        await SendHeartbeatAsync();
    }

    /// <summary>
    /// Removes timed-out clients from mappings.
    /// </summary>
    private void CleanupExpiredClients()
    {
        var expiredIds = new List<short>();

        lock (_mappingsLock)
        {
            foreach (var (id, client) in _mappings)
            {
                if (client.IsTimedOut)
                {
                    expiredIds.Add(id);
                }
            }

            foreach (var id in expiredIds)
            {
                _mappings.TryRemove(id, out _);
            }
        }

        if (expiredIds.Count > 0)
        {
            _logger.Debug("Cleaned up {Count} expired V2 clients", expiredIds.Count);
        }
    }

    /// <summary>
    /// Resets the request counter for rate limiting.
    /// </summary>
    private void ResetRequestCounter()
    {
        _requestCounter.Clear();
    }

    /// <summary>
    /// Sends heartbeat to master server.
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

            _logger.Debug("V2 master server heartbeat sent: {Clients} clients", clientCount);
        }
        catch (Exception ex)
        {
            _logger.Warning("V2 master server heartbeat failed: {Error}", ex.Message);
        }
    }

    /// <summary>
    /// Builds master server URL.
    /// </summary>
    private string BuildMasterServerUrl(int clientCount)
    {
        var parameters = new Dictionary<string, string>
        {
            ["version"] = ProtocolVersion.ToString(),
            ["name"] = _options.Server.Name,
            ["port"] = _options.TunnelV2.Port.ToString(),
            ["clients"] = clientCount.ToString(),
            ["maxclients"] = _options.Server.MaxClients.ToString(),
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
    /// Suppresses ICMP errors on Windows.
    /// </summary>
    private void TrySuppressIcmpErrors()
    {
        try
        {
            _socket.IOControl(SioUdpConnReset, [0, 0, 0, 0], null);
        }
        catch
        {
            // Expected on non-Windows platforms
        }
    }

    public void Dispose()
    {
        _cts.Cancel();
        _heartbeatTimer.Dispose();
        _httpListener.Stop();
        _httpListener.Close();
        _socket.Dispose();
        _cts.Dispose();
    }
}
