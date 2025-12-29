using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Net.Sockets;
using CnCNetServer.Configuration;
using CnCNetServer.Security;
using Serilog;

namespace CnCNetServer.PeerToPeer;

/// <summary>
/// STUN (Session Traversal Utilities for NAT) server for P2P NAT traversal.
///
/// This lightweight STUN implementation allows game clients to discover their
/// public IP address and port, enabling direct peer-to-peer connections.
///
/// Protocol:
/// - Request:  48 bytes with STUN_ID (26262) at bytes 0-1 (network order)
/// - Response: 40 bytes containing:
///   - Bytes 0-3:  Client's public IP (XOR'd with 0x20)
///   - Bytes 4-5:  Client's public port (XOR'd with 0x20)
///   - Bytes 6-7:  STUN_ID (26262)
///   - Bytes 8-39: Random padding
/// </summary>
public sealed class StunServer : IDisposable
{
    // Protocol constants
    private const int StunId = 26262;
    private const int ExpectedRequestSize = 48;
    private const int ResponseSize = 40;
    private const byte XorMask = 0x20;

    // Rate limiting constants
    private const int MaxRequestsPerIp = 20;
    private const int MaxConnectionsGlobal = 5000;

    // Windows-specific IO control code
    private const int SioUdpConnReset = unchecked((int)0x9800000C);

    private readonly int _port;
    private readonly ILogger _logger;
    private readonly IpSecurityManager _securityManager;
    private readonly Socket _socket;
    private readonly byte[] _responseTemplate;
    private readonly CancellationTokenSource _cts = new();

    /// <summary>
    /// Creates a new STUN server on the specified port.
    /// </summary>
    /// <param name="port">UDP port to listen on.</param>
    /// <param name="securityManager">Security manager for rate limiting.</param>
    /// <param name="logger">Logger instance.</param>
    public StunServer(int port, IpSecurityManager securityManager, ILogger logger)
    {
        _port = port;
        _securityManager = securityManager;
        _logger = logger.ForContext<StunServer>().ForContext("Port", port);

        // Create UDP socket
        _socket = new Socket(AddressFamily.InterNetwork, SocketType.Dgram, ProtocolType.Udp);
        _socket.Bind(new IPEndPoint(IPAddress.Any, port));
        TrySuppressIcmpErrors();

        // Initialize response template with random bytes and STUN ID
        _responseTemplate = new byte[ResponseSize];
        Random.Shared.NextBytes(_responseTemplate);

        // Write STUN ID at bytes 6-7 (network byte order)
        BinaryPrimitives.WriteInt16BigEndian(_responseTemplate.AsSpan(6), StunId);
    }

    /// <summary>
    /// Starts the STUN server and begins processing requests.
    /// </summary>
    public async Task RunAsync(CancellationToken cancellationToken = default)
    {
        using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken, _cts.Token);

        _logger.Information("STUN server started on UDP port {Port}", _port);

        var buffer = GC.AllocateArray<byte>(64, pinned: true);
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

                if (result.ReceivedBytes == ExpectedRequestSize)
                {
                    ProcessRequest(buffer.AsSpan(0, result.ReceivedBytes), (IPEndPoint)result.RemoteEndPoint);
                }
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (SocketException ex) when (ex.SocketErrorCode == SocketError.ConnectionReset)
            {
                // ICMP port unreachable - ignore
                continue;
            }
            catch (Exception ex)
            {
                _logger.Error(ex, "STUN server error");
            }
        }

        _logger.Information("STUN server stopped on port {Port}", _port);
    }

    /// <summary>
    /// Processes a STUN request and sends the response.
    /// </summary>
    private void ProcessRequest(ReadOnlySpan<byte> buffer, IPEndPoint remoteEndPoint)
    {
        // Validate remote endpoint
        if (!IsValidEndPoint(remoteEndPoint))
            return;

        // Check rate limits
        if (!_securityManager.IsPingAllowed(remoteEndPoint.Address, MaxRequestsPerIp, MaxConnectionsGlobal))
            return;

        // Verify STUN ID in request (bytes 0-1, network byte order)
        var requestStunId = BinaryPrimitives.ReadInt16BigEndian(buffer);
        if (requestStunId != StunId)
            return;

        // Build response on the stack for efficiency
        Span<byte> response = stackalloc byte[ResponseSize];
        _responseTemplate.CopyTo(response);

        // Write client's public IP address (bytes 0-3)
        var addressBytes = remoteEndPoint.Address.GetAddressBytes();
        addressBytes.CopyTo(response);

        // Write client's public port (bytes 4-5, network byte order)
        BinaryPrimitives.WriteInt16BigEndian(response.Slice(4), (short)remoteEndPoint.Port);

        // Obfuscate first 6 bytes (IP + port) with XOR mask
        for (var i = 0; i < 6; i++)
        {
            response[i] ^= XorMask;
        }

        try
        {
            _socket.SendTo(response, SocketFlags.None, remoteEndPoint);
        }
        catch (SocketException)
        {
            // Ignore send failures
        }
    }

    /// <summary>
    /// Validates that the endpoint is acceptable for STUN response.
    /// </summary>
    private static bool IsValidEndPoint(IPEndPoint endPoint)
    {
        return endPoint.Port != 0 &&
               !endPoint.Address.Equals(IPAddress.Loopback) &&
               !endPoint.Address.Equals(IPAddress.Any) &&
               !endPoint.Address.Equals(IPAddress.Broadcast);
    }

    /// <summary>
    /// Suppresses ICMP port unreachable errors on Windows.
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
        _socket.Dispose();
        _cts.Dispose();
    }
}
