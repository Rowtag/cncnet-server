using System.Net;

namespace CnCNetServer.Models;

/// <summary>
/// Represents a connected client in the tunnel server.
/// Tracks the client's remote endpoint and activity timestamp for timeout detection.
/// </summary>
/// <remarks>
/// Thread-safety: Properties are accessed from multiple threads.
/// LastActivityTicks uses Interlocked for atomic updates.
/// RemoteEndPoint should only be updated under the parent tunnel's lock.
/// </remarks>
public sealed class TunnelClient
{
    private long _lastActivityTicks;
    private readonly int _timeoutSeconds;
    private readonly DateTime _createdAt;

    /// <summary>
    /// The client's remote IP endpoint (IP address and port).
    /// </summary>
    public IPEndPoint? RemoteEndPoint { get; set; }

    /// <summary>
    /// Gets the time when this client was created.
    /// </summary>
    public DateTime CreatedAt => _createdAt;

    /// <summary>
    /// Gets the duration since the client was created.
    /// </summary>
    public TimeSpan SessionDuration => DateTime.UtcNow - _createdAt;

    /// <summary>
    /// Creates a new tunnel client with the specified timeout.
    /// </summary>
    /// <param name="timeoutSeconds">Timeout in seconds after which the client is considered inactive.</param>
    public TunnelClient(int timeoutSeconds = 60)
    {
        _timeoutSeconds = timeoutSeconds;
        _createdAt = DateTime.UtcNow;
        UpdateLastActivity();
    }

    /// <summary>
    /// Creates a new tunnel client with a specific remote endpoint.
    /// </summary>
    /// <param name="remoteEndPoint">The client's remote IP endpoint.</param>
    /// <param name="timeoutSeconds">Timeout in seconds.</param>
    public TunnelClient(IPEndPoint remoteEndPoint, int timeoutSeconds = 60)
        : this(timeoutSeconds)
    {
        RemoteEndPoint = remoteEndPoint;
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
