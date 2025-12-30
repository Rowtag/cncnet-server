using System.Collections.Concurrent;

namespace CnCNetServer.Logging;

/// <summary>
/// Tracks successful tunnel sessions for display in the web dashboard.
/// Separate instance per tunnel (V2/V3) for independent tracking.
/// </summary>
public sealed class SessionLog
{
    private readonly ConcurrentQueue<SessionEntry> _entries = new();
    private readonly int _maxEntries;
    private readonly string _tunnelName;

    /// <summary>
    /// Session log for V2 Tunnel.
    /// </summary>
    public static SessionLog V2 { get; } = new("V2", 500);

    /// <summary>
    /// Session log for V3 Tunnel.
    /// </summary>
    public static SessionLog V3 { get; } = new("V3", 500);

    /// <summary>
    /// Current display limit for entries shown in UI.
    /// </summary>
    public int DisplayLimit { get; set; } = 50;

    /// <summary>
    /// Gets the tunnel name (V2 or V3).
    /// </summary>
    public string TunnelName => _tunnelName;

    public SessionLog(string tunnelName, int maxEntries = 500)
    {
        _tunnelName = tunnelName;
        _maxEntries = maxEntries;
    }

    /// <summary>
    /// Records a new session start. Returns a session ID for tracking.
    /// </summary>
    public Guid StartSession(string ipAddress)
    {
        var sessionId = Guid.NewGuid();
        var entry = new SessionEntry
        {
            SessionId = sessionId,
            IpAddress = ipAddress,
            StartTime = DateTime.UtcNow,
            Status = SessionStatus.Active
        };

        _entries.Enqueue(entry);

        // Enforce max entries
        while (_entries.Count > _maxEntries)
        {
            _entries.TryDequeue(out _);
        }

        return sessionId;
    }

    /// <summary>
    /// Records a completed session with duration.
    /// </summary>
    public void LogSession(string ipAddress, TimeSpan duration)
    {
        var entry = new SessionEntry
        {
            SessionId = Guid.NewGuid(),
            IpAddress = ipAddress,
            StartTime = DateTime.UtcNow - duration,
            EndTime = DateTime.UtcNow,
            Duration = duration,
            Status = SessionStatus.Completed
        };

        _entries.Enqueue(entry);

        // Enforce max entries
        while (_entries.Count > _maxEntries)
        {
            _entries.TryDequeue(out _);
        }
    }

    /// <summary>
    /// Gets the most recent session entries, limited by DisplayLimit.
    /// </summary>
    public IEnumerable<SessionEntry> GetEntries()
    {
        return _entries
            .Reverse()
            .Take(DisplayLimit)
            .ToList();
    }

    /// <summary>
    /// Gets available display limits for UI dropdown.
    /// </summary>
    public static IEnumerable<int> GetAvailableLimits()
    {
        yield return 50;
        yield return 100;
        yield return 200;
        yield return 500;
    }

    /// <summary>
    /// Gets the total number of sessions logged.
    /// </summary>
    public int TotalCount => _entries.Count;
}

/// <summary>
/// A single session entry for display.
/// </summary>
public sealed class SessionEntry
{
    public Guid SessionId { get; init; }
    public required string IpAddress { get; init; }
    public DateTime StartTime { get; init; }
    public DateTime? EndTime { get; init; }
    public TimeSpan? Duration { get; init; }
    public SessionStatus Status { get; init; }

    /// <summary>
    /// Formats the duration for display.
    /// </summary>
    public string DurationFormatted
    {
        get
        {
            if (Duration == null)
                return "active";

            var d = Duration.Value;
            if (d.TotalHours >= 1)
                return $"{(int)d.TotalHours}h {d.Minutes}m {d.Seconds}s";
            if (d.TotalMinutes >= 1)
                return $"{d.Minutes}m {d.Seconds}s";
            return $"{d.Seconds}s";
        }
    }
}

public enum SessionStatus
{
    Active,
    Completed
}
