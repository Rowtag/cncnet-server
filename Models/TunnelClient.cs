using System.Net;
using CnCNetServer.Security;

namespace CnCNetServer.Models;

/// <summary>
/// Represents a connected client in the tunnel server.
/// Tracks the client's remote endpoint and activity timestamp for timeout detection.
/// </summary>
/// <remarks>
/// Thread-safety: Properties are accessed from multiple threads.
/// LastActivityTicks uses Interlocked for atomic updates.
/// The remote endpoint should only be updated under the parent tunnel's lock.
///
/// The endpoint is held in three forms because each is on a path where the others would cost
/// something: the numeric address and port for the per-packet comparison, a SocketAddress for
/// sending without re-serialising an IPEndPoint on every relay, and an IPEndPoint only for the
/// cold paths (statistics, tracing) that want a real address object.
/// </remarks>
public sealed class TunnelClient
{
    private long _lastActivityTicks;
    private readonly int _timeoutSeconds;
    private IPEndPoint? _remoteEndPoint;

    /// <summary>
    /// The client's remote IPv4 address in numeric form.
    /// </summary>
    public uint RemoteAddress { get; private set; }

    /// <summary>
    /// The client's remote port.
    /// </summary>
    public int RemotePort { get; private set; }

    /// <summary>
    /// The client's remote endpoint in the form used to send to it.
    /// </summary>
    public SocketAddress? RemoteSocketAddress { get; private set; }

    /// <summary>
    /// Whether a remote endpoint has been recorded for this client.
    /// </summary>
    public bool HasRemote => RemoteSocketAddress != null;

    /// <summary>
    /// The client's remote IP endpoint, built on demand. Only for cold paths - the packet paths
    /// use <see cref="RemoteAddress"/>, <see cref="RemotePort"/> and <see cref="RemoteSocketAddress"/>.
    /// </summary>
    public IPEndPoint? RemoteEndPoint
    {
        get
        {
            if (!HasRemote)
                return null;

            var a = RemoteAddress;
            return _remoteEndPoint ??= new IPEndPoint(
                new IPAddress([(byte)(a >> 24), (byte)(a >> 16), (byte)(a >> 8), (byte)a]),
                RemotePort);
        }
    }

    /// <summary>
    /// Creates a new tunnel client with the specified timeout.
    /// </summary>
    /// <param name="timeoutSeconds">Timeout in seconds after which the client is considered inactive.</param>
    public TunnelClient(int timeoutSeconds = 60)
    {
        _timeoutSeconds = timeoutSeconds;
        UpdateLastActivity();
    }

    /// <summary>
    /// Records where this client is reachable.
    /// </summary>
    /// <param name="socketAddress">
    /// The address the packet arrived on. Copied rather than retained: the receive loop reuses one
    /// instance for every datagram, so keeping a reference would leave this client pointing at
    /// whoever sent the next packet.
    /// </param>
    public void SetRemote(uint address, int port, SocketAddress socketAddress)
    {
        RemoteAddress = address;
        RemotePort = port;
        RemoteSocketAddress = Copy(socketAddress);
        _remoteEndPoint = null;
    }

    /// <summary>
    /// Records where this client is reachable, from an endpoint the caller already holds. For the
    /// V2 tunnel, whose receive path still works in <see cref="IPEndPoint"/>s.
    /// </summary>
    public void SetRemote(IPEndPoint endPoint)
    {
        IpRangeSet.TryGetKey(endPoint.Address, out var address);

        RemoteAddress = address;
        RemotePort = endPoint.Port;
        RemoteSocketAddress = endPoint.Serialize();
        _remoteEndPoint = endPoint;
    }

    /// <summary>
    /// Whether this client is currently reachable at the given address and port.
    /// </summary>
    public bool Matches(uint address, int port) => RemoteAddress == address && RemotePort == port;

    private static SocketAddress Copy(SocketAddress source)
    {
        var copy = new SocketAddress(source.Family, source.Size);
        source.Buffer.Span.Slice(0, source.Size).CopyTo(copy.Buffer.Span);
        return copy;
    }

    /// <summary>
    /// Checks if the client has timed out (no activity within the timeout period).
    /// </summary>
    public bool IsTimedOut
    {
        get
        {
            var lastActivity = Interlocked.Read(ref _lastActivityTicks);
            var elapsed = TimeSpan.FromTicks(DateTime.UtcNow.Ticks - lastActivity);
            return elapsed.TotalSeconds >= _timeoutSeconds;
        }
    }

    /// <summary>
    /// Gets the time elapsed since the last activity.
    /// </summary>
    public TimeSpan TimeSinceLastActivity
    {
        get
        {
            var lastActivity = Interlocked.Read(ref _lastActivityTicks);
            return TimeSpan.FromTicks(DateTime.UtcNow.Ticks - lastActivity);
        }
    }

    /// <summary>
    /// Updates the last activity timestamp to the current time.
    /// Thread-safe using Interlocked operations.
    /// </summary>
    public void UpdateLastActivity()
    {
        Interlocked.Exchange(ref _lastActivityTicks, DateTime.UtcNow.Ticks);
    }
}
